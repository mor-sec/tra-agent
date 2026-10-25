---
classification: OFFICIAL
owner: People and Culture systems lead
---

# Team leave calendar: Solution Design (example)

**OFFICIAL.** This is a fictional design used to exercise the TRA agent.

## 1. Purpose

Managers see when their team members are on planned leave so they can plan rosters.
The calendar shows a name and the leave dates only. Leave type, reasons and balances
stay in the HR system of record and are not copied.

## 2. Components

| Component | Description | Hosting |
|---|---|---|
| Staff member | Employee using a managed laptop on the corporate network or VPN | Corporate |
| Calendar web app | Internal web app on Azure App Service, reachable only through the corporate network via a private endpoint. Sign-in with Entra ID SSO and the corporate conditional access policy | Azure |
| Calendar database | Azure SQL Database holding name, team and leave start and end dates | Azure |
| HR system | The HR system of record. Pushes approved leave dates nightly | SaaS |
| Sync function | Azure Function that receives the nightly export over HTTPS with a client certificate and writes it to the calendar database | Azure |

## 3. Data flows

1. Staff member signs in through Entra ID and views the calendar for their team.
2. Calendar web app reads leave entries for the signed-in user's team from the database using a managed identity.
3. HR system sends the nightly approved-leave export to the sync function.
4. Sync function writes leave entries to the calendar database using a managed identity.
5. All components send logs to the shared Log Analytics workspace.

## 4. Security notes

- Managers see only their own team; team membership comes from the HR export.
- No public endpoint. The app is not reachable from the internet.
- The export contains names and dates only.
