# AirgunMatches.com

Public calendar of airgun competitions across the United States, with
coordinator-submitted events held for manual approval.

## Current production (pre-migration)
- Frontend: two static HTML files served by Netlify (project `airgunmatches`)
- Data: Supabase Postgres, table `public.events`
- Admin auth: Supabase Auth + `public.admins` allowlist
- Spam control: hidden honeypot field
