-- ============================================================================
-- Kampung Terpadu - Skema Database Supabase (PostgreSQL + Auth + RLS)
-- Jalankan seluruh skrip ini di Supabase Dashboard -> SQL Editor -> New Query
-- ============================================================================

-- 1. Schema internal untuk fungsi helper keamanan (tidak terekspos ke Data API)
create schema if not exists private;

-- 2. Tabel data utama
create table if not exists public.kk (
  id bigint generated always as identity primary key,
  nama text not null check (char_length(trim(nama)) > 0),
  blok text not null default '',
  hp text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.kas (
  id bigint generated always as identity primary key,
  tgl date not null default current_date,
  ket text not null check (char_length(trim(ket)) > 0),
  jenis text not null check (jenis in ('masuk', 'keluar')),
  jml bigint not null check (jml > 0),
  ref_pinjam bigint,
  ref_ke integer,
  created_at timestamptz not null default now()
);

create table if not exists public.ronda (
  id bigint generated always as identity primary key,
  hari text not null check (hari in ('Senin','Selasa','Rabu','Kamis','Jumat','Sabtu','Minggu')),
  kk_id bigint not null references public.kk(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (hari, kk_id)
);

create table if not exists public.pinjam (
  id bigint generated always as identity primary key,
  kk_id bigint not null references public.kk(id) on delete cascade,
  tgl date not null default current_date,
  pokok bigint not null check (pokok > 0),
  tenor integer not null check (tenor >= 1),
  bunga numeric(6,2) not null default 0 check (bunga >= 0),
  bayar integer not null default 0 check (bayar >= 0 and bayar <= tenor),
  created_at timestamptz not null default now()
);

-- Tambahkan FK opsional dari kas.ref_pinjam -> pinjam.id (set null jika pinjaman dihapus)
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'kas_ref_pinjam_fkey'
  ) then
    alter table public.kas
      add constraint kas_ref_pinjam_fkey
      foreign key (ref_pinjam) references public.pinjam(id) on delete set null;
  end if;
end $$;

create table if not exists public.info (
  id bigint generated always as identity primary key,
  judul text not null check (char_length(trim(judul)) > 0),
  isi text not null check (char_length(trim(isi)) > 0),
  tgl date not null default current_date,
  created_at timestamptz not null default now()
);

-- 3. Tabel profil pengguna & role (super_admin vs viewer)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  nama text not null default '',
  role text not null default 'viewer' check (role in ('super_admin', 'viewer')),
  kk_id bigint references public.kk(id) on delete set null,
  created_at timestamptz not null default now()
);

-- 4. Index untuk foreign key & query yang sering dipakai
create index if not exists ronda_kk_id_idx on public.ronda (kk_id);
create index if not exists pinjam_kk_id_idx on public.pinjam (kk_id);
create index if not exists kas_tgl_idx on public.kas (tgl desc, id desc);
create index if not exists kas_ref_pinjam_idx on public.kas (ref_pinjam) where ref_pinjam is not null;
create index if not exists info_tgl_idx on public.info (tgl desc, id desc);
create index if not exists profiles_kk_id_idx on public.profiles (kk_id);
create index if not exists profiles_role_idx on public.profiles (role);

-- 5. Helper pengecekan Super Admin (SECURITY DEFINER di schema private)
create or replace function private.is_super_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles
    where id = (select auth.uid())
      and role = 'super_admin'
  );
$$;

revoke all on function private.is_super_admin() from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.is_super_admin() to authenticated;

-- 6. Trigger otomatis membuat profile 'viewer' (lihat saja) saat user mendaftar
create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, nama, role)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(nullif(trim(new.raw_user_meta_data ->> 'nama'), ''), split_part(coalesce(new.email, ''), '@', 1)),
    'viewer'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_user();

-- 7. Fungsi atomik untuk bayar & batal angsuran (SECURITY INVOKER -> patuh RLS!)
create or replace function public.bayar_angsuran(p_pinjam_id bigint, p_tgl date default current_date)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_p public.pinjam%rowtype;
  v_kk_nama text;
  v_kk_blok text;
  v_label text;
  v_nom bigint;
begin
  select * into v_p from public.pinjam where id = p_pinjam_id for update;
  if not found then
    raise exception 'Data pinjaman tidak ditemukan';
  end if;
  if v_p.bayar >= v_p.tenor then
    raise exception 'Pinjaman sudah lunas';
  end if;

  select nama, blok into v_kk_nama, v_kk_blok from public.kk where id = v_p.kk_id;
  v_label := coalesce(v_kk_nama, 'Warga') || case when coalesce(v_kk_blok, '') <> '' then ' (' || v_kk_blok || ')' else '' end;
  v_nom := round(v_p.pokok * (1 + v_p.bunga / 100.0) / v_p.tenor)::bigint;

  update public.pinjam
  set bayar = v_p.bayar + 1
  where id = v_p.id;

  insert into public.kas (tgl, ket, jenis, jml, ref_pinjam, ref_ke)
  values (coalesce(p_tgl, current_date), 'Angsuran ' || v_label || ' ke-' || (v_p.bayar + 1), 'masuk', v_nom, v_p.id, v_p.bayar + 1);
end;
$$;

create or replace function public.batal_angsuran(p_pinjam_id bigint)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_p public.pinjam%rowtype;
  v_kas_id bigint;
begin
  select * into v_p from public.pinjam where id = p_pinjam_id for update;
  if not found then
    raise exception 'Data pinjaman tidak ditemukan';
  end if;
  if v_p.bayar <= 0 then
    raise exception 'Belum ada angsuran yang tercatat';
  end if;

  select id into v_kas_id
  from public.kas
  where ref_pinjam = v_p.id and ref_ke = v_p.bayar
  order by id desc
  limit 1;

  if v_kas_id is not null then
    delete from public.kas where id = v_kas_id;
  end if;

  update public.pinjam
  set bayar = v_p.bayar - 1
  where id = v_p.id;
end;
$$;

-- 8. Hak akses tabel (tolak anon sepenuhnya, hanya authenticated yang boleh akses)
revoke all on public.kk, public.kas, public.ronda, public.pinjam, public.info, public.profiles from anon;
grant usage on schema public to authenticated;
grant select on public.kk, public.kas, public.ronda, public.pinjam, public.info, public.profiles to authenticated;
grant insert, update, delete on public.kk, public.kas, public.ronda, public.pinjam, public.info to authenticated;
grant update on public.profiles to authenticated;
grant execute on function public.bayar_angsuran(bigint, date) to authenticated;
grant execute on function public.batal_angsuran(bigint) to authenticated;

-- 9. Aktifkan Row Level Security (RLS) pada semua tabel
alter table public.kk enable row level security;
alter table public.kas enable row level security;
alter table public.ronda enable row level security;
alter table public.pinjam enable row level security;
alter table public.info enable row level security;
alter table public.profiles enable row level security;

-- 10. Kebijakan RLS:
--     - Wajib login (authenticated, bukan anonymous) untuk melihat data
--     - Hanya super_admin yang boleh menambah, mengubah, atau menghapus data

-- Tabel KK
drop policy if exists "kk_select_auth" on public.kk;
create policy "kk_select_auth" on public.kk for select to authenticated
  using ((select auth.uid()) is not null and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false);
drop policy if exists "kk_insert_admin" on public.kk;
create policy "kk_insert_admin" on public.kk for insert to authenticated
  with check ((select private.is_super_admin()));
drop policy if exists "kk_update_admin" on public.kk;
create policy "kk_update_admin" on public.kk for update to authenticated
  using ((select private.is_super_admin())) with check ((select private.is_super_admin()));
drop policy if exists "kk_delete_admin" on public.kk;
create policy "kk_delete_admin" on public.kk for delete to authenticated
  using ((select private.is_super_admin()));

-- Tabel KAS
drop policy if exists "kas_select_auth" on public.kas;
create policy "kas_select_auth" on public.kas for select to authenticated
  using ((select auth.uid()) is not null and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false);
drop policy if exists "kas_insert_admin" on public.kas;
create policy "kas_insert_admin" on public.kas for insert to authenticated
  with check ((select private.is_super_admin()));
drop policy if exists "kas_update_admin" on public.kas;
create policy "kas_update_admin" on public.kas for update to authenticated
  using ((select private.is_super_admin())) with check ((select private.is_super_admin()));
drop policy if exists "kas_delete_admin" on public.kas;
create policy "kas_delete_admin" on public.kas for delete to authenticated
  using ((select private.is_super_admin()));

-- Tabel RONDA
drop policy if exists "ronda_select_auth" on public.ronda;
create policy "ronda_select_auth" on public.ronda for select to authenticated
  using ((select auth.uid()) is not null and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false);
drop policy if exists "ronda_insert_admin" on public.ronda;
create policy "ronda_insert_admin" on public.ronda for insert to authenticated
  with check ((select private.is_super_admin()));
drop policy if exists "ronda_update_admin" on public.ronda;
create policy "ronda_update_admin" on public.ronda for update to authenticated
  using ((select private.is_super_admin())) with check ((select private.is_super_admin()));
drop policy if exists "ronda_delete_admin" on public.ronda;
create policy "ronda_delete_admin" on public.ronda for delete to authenticated
  using ((select private.is_super_admin()));

-- Tabel PINJAM
drop policy if exists "pinjam_select_auth" on public.pinjam;
create policy "pinjam_select_auth" on public.pinjam for select to authenticated
  using ((select auth.uid()) is not null and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false);
drop policy if exists "pinjam_insert_admin" on public.pinjam;
create policy "pinjam_insert_admin" on public.pinjam for insert to authenticated
  with check ((select private.is_super_admin()));
drop policy if exists "pinjam_update_admin" on public.pinjam;
create policy "pinjam_update_admin" on public.pinjam for update to authenticated
  using ((select private.is_super_admin())) with check ((select private.is_super_admin()));
drop policy if exists "pinjam_delete_admin" on public.pinjam;
create policy "pinjam_delete_admin" on public.pinjam for delete to authenticated
  using ((select private.is_super_admin()));

-- Tabel INFO
drop policy if exists "info_select_auth" on public.info;
create policy "info_select_auth" on public.info for select to authenticated
  using ((select auth.uid()) is not null and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false);
drop policy if exists "info_insert_admin" on public.info;
create policy "info_insert_admin" on public.info for insert to authenticated
  with check ((select private.is_super_admin()));
drop policy if exists "info_update_admin" on public.info;
create policy "info_update_admin" on public.info for update to authenticated
  using ((select private.is_super_admin())) with check ((select private.is_super_admin()));
drop policy if exists "info_delete_admin" on public.info;
create policy "info_delete_admin" on public.info for delete to authenticated
  using ((select private.is_super_admin()));

-- Tabel PROFILES (user hanya baca profil sendiri; super_admin baca & ubah semua profil)
drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles for select to authenticated
  using ((select auth.uid()) = id or (select private.is_super_admin()));
drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin" on public.profiles for update to authenticated
  using ((select private.is_super_admin())) with check ((select private.is_super_admin()));

-- ============================================================================
-- PENTING: Setelah Super Admin mendaftar/dibuat di Authentication -> Users,
-- jalankan perintah berikut (ganti dengan email Super Admin Anda):
--
--   update public.profiles
--   set role = 'super_admin'
--   where email = 'email-super-admin@contoh.com';
-- ============================================================================
