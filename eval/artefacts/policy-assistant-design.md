---
classification: OFFICIAL_SENSITIVE
owner: Head of Workplace Technology
---

# Policy assistant: Solution Design (example)

**OFFICIAL: Sensitive.** This is a fictional design used to exercise the TRA agent.

## 1. Purpose

Staff ask questions about internal policies and procedures in Microsoft Teams and get
answers with links to the source pages. The assistant can also raise a service desk
ticket on the user's behalf when the answer says a request is needed.

## 2. Components

| Component | Description | Hosting |
|---|---|---|
| Staff member | Employee signed in to Teams with Entra ID | Corporate |
| Teams bot | Azure Bot Service channel that relays messages to the assistant | Azure |
| Policy assistant | Agent on Azure AI Foundry using a GPT model. Has two tools: search the policy index, and create a service desk ticket | Azure |
| Policy index | Azure AI Search index of chunked Confluence policy pages, refreshed nightly | Azure |
| Indexer | Scheduled job that reads all pages in the POLICY Confluence space and writes chunks and embeddings to the index | Azure |
| Confluence | Wiki holding policy pages. Any staff member can edit pages in the POLICY space; changes are not reviewed before publishing | SaaS |
| Service desk | ITSM tool. The assistant creates tickets with a service account that can create tickets for any user | SaaS |

## 3. Data flows

1. Staff member sends a question in Teams; the bot forwards it with the user's Entra object ID.
2. Policy assistant searches the policy index and passes the top chunks to the model.
3. Policy assistant returns the answer and source links to the user.
4. When the model decides a request is needed, the assistant creates a ticket in the service desk with the service account, naming the user as requester.
5. The indexer reads the POLICY space with a Confluence API token and updates the index.
6. Prompts and answers are logged to Application Insights for 90 days.

## 4. Security notes

- The system prompt tells the model to answer only from retrieved policy content.
- No content filtering beyond the Foundry defaults.
- The index has no per-document permissions; every chunk is visible to every user.
- The Confluence API token is stored as an app setting on the indexer.
