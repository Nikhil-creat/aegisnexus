# Upload to GitHub and publish with GitHub Pages

## 1. One-time setup
1. Install Git: https://git-scm.com/downloads
2. Tell Git who you are:
   ```
   git config --global user.name "Nikhil Chary Sriramoju"
   git config --global user.email "your-github-email@example.com"
   ```

## 2. Create the empty repository on GitHub
1. Go to https://github.com/new
2. Repository name: `aegisnexus`
3. Choose **Public** (free GitHub Pages needs a public repo).
4. Leave "Add a README", ".gitignore" and "license" **unchecked**, because the project already has them.
5. Click **Create repository**.

## 3. Push the project
Extract the zip, open a terminal (PowerShell, Terminal or Git Bash) **inside the extracted `aegisnexus` folder**, then run:

```
git init -b main
git add .
git commit -m "Initial commit: AegisNexus"
git remote add origin https://github.com/Nikhil-creat/aegisnexus.git
git push -u origin main
```

GitHub does not accept your account password for pushes. When asked to sign in, use the browser sign-in window that Git Credential Manager opens, or paste a Personal Access Token (GitHub > Settings > Developer settings > Personal access tokens > Fine-grained, with **Contents: read and write** on this repo).

## 4. Turn on GitHub Pages
1. Open the repo, then **Settings > Pages**.
2. Under **Build and deployment**, set **Source** to **Deploy from a branch**.
3. Branch: **main**, folder: **/docs**, then **Save**.
4. Wait one to two minutes and refresh. The page shows your link:

   **https://nikhil-creat.github.io/aegisnexus/**

The link opens the landing page with the 3D lab and your credentials. The working console is at **https://nikhil-creat.github.io/aegisnexus/console.html**. Both are static (recorded investigations, in-browser knowledge search). Login, saved cases and file upload appear when you run the Docker stack.

## 5. Change the details shown on the site
Open `docs/assets/profile.js`, edit your name, links or certifications, then commit and push (section 6). Pages updates in a minute or two.

## 5b. Check that CI is green
Open the **Actions** tab. The `CI` workflow runs the tests and a Docker build after each push. A green tick means the project builds.

## 6. Updating later
```
git add .
git commit -m "Describe your change"
git push
```
Pages redeploys automatically.

## Troubleshooting
* **404 on the Pages link**: confirm the folder is `/docs` and that `docs/index.html` is on GitHub. Wait a couple of minutes.
* **Page loads but says "Recorded demo"**: expected on GitHub Pages.
* **`git push` rejected**: the repo was created with a README. Run `git pull origin main --allow-unrelated-histories`, then push again.
* **Never upload `.env`**: it is already in `.gitignore`.
