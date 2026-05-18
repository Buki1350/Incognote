    const AUTH_URL = "http://localhost:3001";
    const NOTES_URL = "http://localhost:3002";

    const state = {
      token: localStorage.getItem("incognote_token") || "",
      userId: parseInt(localStorage.getItem("incognote_id") || "0", 10),
      username: localStorage.getItem("incognote_username") || "",
      email: localStorage.getItem("incognote_email") || "",
      role: localStorage.getItem("incognote_role") || "",
      mode: "login",
      selectedNote: null,
      notes: [],
      friends: [],
      invites: [],
      messages: []
    };

    const els = {
      statusBar: document.getElementById("status-bar"),
      authSection: document.getElementById("auth-section"),
      appSection: document.getElementById("app-section"),
      authTitle: document.getElementById("auth-title"),
      authForm: document.getElementById("auth-form"),
      registerUsernameWrap: document.getElementById("register-username-wrap"),
      registerConfirmPasswordWrap: document.getElementById("register-confirm-password-wrap"),
      authEmail: document.getElementById("auth-email"),
      authUsername: document.getElementById("auth-username"),
      authPassword: document.getElementById("auth-password"),
      authConfirmPassword: document.getElementById("auth-confirm-password"),
      verifyToken: document.getElementById("verify-token"),
      verifyEmailBtn: document.getElementById("verify-email-btn"),
      resendTokenBtn: document.getElementById("resend-token-btn"),
      forgotPasswordSection: document.getElementById("forgot-password-section"),
      forgotPasswordBtn: document.getElementById("forgot-password-btn"),
      resetPasswordSection: document.getElementById("reset-password-section"),
      resetToken: document.getElementById("reset-token"),
      newPassword: document.getElementById("new-password"),
      confirmNewPassword: document.getElementById("confirm-new-password"),
      resetPasswordSubmitBtn: document.getElementById("reset-password-submit-btn"),
      authSubmit: document.getElementById("auth-submit"),
      authToggle: document.getElementById("auth-toggle"),
      userPill: document.getElementById("user-pill"),
      logoutBtn: document.getElementById("logout-btn"),
      createForm: document.getElementById("create-form"),
      createContent: document.getElementById("create-content"),
      noteList: document.getElementById("note-list"),
      refreshBtn: document.getElementById("refresh-btn"),
      viewerEmpty: document.getElementById("viewer-empty"),
      viewerForm: document.getElementById("viewer-form"),
      viewerMeta: document.getElementById("viewer-meta"),
      viewerContent: document.getElementById("viewer-content"),
      saveBtn: document.getElementById("save-btn"),
      deleteBtn: document.getElementById("delete-btn"),
      shareFriend: document.getElementById("share-friend"),
      sharePermission: document.getElementById("share-permission"),
      shareBtn: document.getElementById("share-btn"),
      globalPrivateKey: document.getElementById("global-private-key"),
      privateKeyFile: document.getElementById("private-key-file"),
      privateKeyPath: document.getElementById("private-key-path"),
      friendIdentifier: document.getElementById("friend-identifier"),
      addFriendBtn: document.getElementById("add-friend-btn"),
      refreshFriendsBtn: document.getElementById("refresh-friends-btn"),
      friendList: document.getElementById("friend-list"),
      refreshInvitesBtn: document.getElementById("refresh-invites-btn"),
      inviteList: document.getElementById("invite-list"),
      messageRecipient: document.getElementById("message-recipient"),
      messageContent: document.getElementById("message-content"),
      sendMessageBtn: document.getElementById("send-message-btn"),
      refreshMessagesBtn: document.getElementById("refresh-messages-btn"),
      messageList: document.getElementById("message-list"),
      navNotesBtn: document.getElementById("nav-notes-btn"),
      navFriendsBtn: document.getElementById("nav-friends-btn"),
      navMessagesBtn: document.getElementById("nav-messages-btn"),
      navKeysBtn: document.getElementById("nav-keys-btn"),
      navAdminBtn: document.getElementById("nav-admin-btn"),
      notesView: document.getElementById("notes-view"),
      friendsView: document.getElementById("friends-view"),
      messagesView: document.getElementById("messages-view"),
      keysView: document.getElementById("keys-view"),
      adminView: document.getElementById("admin-view"),
      keyValue: document.getElementById("key-value"),
      saveKeyBtn: document.getElementById("save-key-btn"),
      noteEncryptBtn: document.getElementById("note-encrypt-btn"),
      noteKeyFile: document.getElementById("note-key-file"),
      noteKeyLabel: document.getElementById("note-key-label")
    };

    let noteEncryptKey = "";
    let pollTimer = null;

    function switchTab(tab) {
      els.notesView.classList.toggle("active", tab === "notes");
      els.friendsView.classList.toggle("active", tab === "friends");
      els.messagesView.classList.toggle("active", tab === "messages");
      els.keysView.classList.toggle("active", tab === "keys");
      els.adminView.classList.toggle("active", tab === "admin");
      els.navNotesBtn.classList.toggle("btn-primary", tab === "notes");
      els.navNotesBtn.classList.toggle("btn-secondary", tab !== "notes");
      els.navFriendsBtn.classList.toggle("btn-primary", tab === "friends");
      els.navFriendsBtn.classList.toggle("btn-secondary", tab !== "friends");
      els.navMessagesBtn.classList.toggle("btn-primary", tab === "messages");
      els.navMessagesBtn.classList.toggle("btn-secondary", tab !== "messages");
      els.navKeysBtn.classList.toggle("btn-primary", tab === "keys");
      els.navKeysBtn.classList.toggle("btn-secondary", tab !== "keys");
      els.navAdminBtn.classList.toggle("btn-primary", tab === "admin");
      els.navAdminBtn.classList.toggle("btn-secondary", tab !== "admin");
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      if (state.token) {
        if (tab === "notes") refreshNotes();
        if (tab === "friends") { refreshFriends(); refreshInvites(); }
        if (tab === "messages") {
          refreshMessages();
          pollTimer = setInterval(refreshMessages, 30000);
        }
      }
      if (tab === "admin" && state.role === "admin") {
        loadAdminData();
      }
    }

    function showStatus(message, kind = "ok") {
      els.statusBar.textContent = message;
      els.statusBar.className = `status ${kind === "err" ? "status-err" : "status-ok"}`;
      els.statusBar.classList.remove("hidden");
      window.setTimeout(() => {
        els.statusBar.classList.add("hidden");
      }, 3800);
    }

    function setAuthMode(mode) {
      state.mode = mode;
      const isLogin = mode === "login";
      els.authTitle.textContent = isLogin ? "Login" : "Register";
      els.authSubmit.textContent = isLogin ? "Login" : "Register";
      els.authToggle.textContent = isLogin ? "Need an account?" : "Have an account?";
      els.registerUsernameWrap.classList.toggle("hidden", isLogin);
      els.registerConfirmPasswordWrap.classList.toggle("hidden", isLogin);
      els.authUsername.required = !isLogin;
      els.authConfirmPassword.required = !isLogin;
      els.authPassword.autocomplete = isLogin ? "current-password" : "new-password";
    }

    function setSession({ token, user_id, username, email, role }) {
      state.token = token;
      state.userId = user_id || 0;
      state.username = username;
      state.email = email;
      state.role = role;
      localStorage.setItem("incognote_id", String(state.userId));
      localStorage.setItem("incognote_token", token);
      localStorage.setItem("incognote_username", username);
      localStorage.setItem("incognote_email", email);
      localStorage.setItem("incognote_role", role);
    }

    function clearSession() {
      state.token = "";
      state.userId = 0;
      state.username = "";
      state.email = "";
      state.role = "";
      state.selectedNote = null;
      state.notes = [];
      state.friends = [];
      state.invites = [];
      state.messages = [];
      noteEncryptKey = "";
      els.noteKeyFile.value = "";
      els.noteKeyLabel.classList.add("hidden");
      localStorage.removeItem("incognote_token");
      localStorage.removeItem("incognote_id");
      localStorage.removeItem("incognote_username");
      localStorage.removeItem("incognote_email");
      localStorage.removeItem("incognote_role");
    }

    function updateLayout() {
      const authenticated = Boolean(state.token);
      els.authSection.classList.toggle("hidden", authenticated);
      els.appSection.classList.toggle("hidden", !authenticated);
      els.userPill.classList.toggle("hidden", !authenticated);
      els.logoutBtn.classList.toggle("hidden", !authenticated);
      els.navAdminBtn.style.display = state.role === "admin" ? "block" : "none";
      if (authenticated) {
        els.userPill.textContent = `${state.username} <${state.email}> (${state.role})`;
        if (state.role === "admin") {
          loadAdminData();
        }
      }
      if (!authenticated) {
        resetViewer();
        renderFriends();
        renderInvites();
        renderMessages();
      }
    }

    function setCookie(name, value, days = 365) {
      const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toUTCString();
      document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
    }

    function getCookie(name) {
      const row = document.cookie
        .split(";")
        .map((value) => value.trim())
        .find((value) => value.startsWith(`${name}=`));
      return row ? decodeURIComponent(row.split("=")[1]) : "";
    }

    function currentPrivateKey() {
      return els.globalPrivateKey.value.trim();
    }

    function persistPrivateKey() {
      sessionStorage.setItem("incognote_private_key", currentPrivateKey());
    }

    async function authRequest(path, body) {
      const response = await fetch(`${AUTH_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const payload = await safeJson(response);
      if (!response.ok) {
        throw new Error(payload.message || `Auth error ${response.status}`);
      }
      return payload;
    }

    async function notesRequest(path, options = {}) {
      const response = await fetch(`${NOTES_URL}${path}`, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${state.token}`,
          ...(options.headers || {})
        }
      });

      const payload = await safeJson(response);

      if (response.status === 401) {
        clearSession();
        updateLayout();
        throw new Error("Session expired. Please login again.");
      }

      if (!response.ok) {
        throw new Error(payload.message || `Notes error ${response.status}`);
      }

      return payload;
    }

    async function safeJson(response) {
      try {
        return await response.json();
      } catch {
        return {};
      }
    }

    function resetViewer() {
      state.selectedNote = null;
      renderNotes();
      els.viewerForm.classList.add("hidden");
      els.viewerEmpty.classList.remove("hidden");
      els.viewerContent.value = "";
      els.shareFriend.value = "";
      els.viewerMeta.textContent = "";
    }

    function noteChipClass(permission) {
      if (permission === "owner") return "chip-owner";
      if (permission === "write") return "chip-write";
      if (permission === "admin") return "chip-admin";
      return "chip-read";
    }

    function renderNotes() {
      els.noteList.innerHTML = "";
      if (!state.notes.length) {
        const empty = document.createElement("p");
        empty.className = "mono";
        empty.textContent = "No notes yet. Create one on the left.";
        els.noteList.appendChild(empty);
        return;
      }

      state.notes.forEach((note, index) => {
        const item = document.createElement("article");
        item.className = `note-item${state.selectedNote?.id === note.id ? " note-item-selected" : ""}`;
        item.style.animationDelay = `${index * 40}ms`;

        const meta = document.createElement("div");
        meta.className = "note-meta";

        const left = document.createElement("span");
        left.textContent = `#${note.id} · ${new Date(note.created_at).toLocaleString()}`;

        const chip = document.createElement("span");
        chip.className = `chip ${noteChipClass(note.permission)}`;
        chip.textContent = `${note.permission}${note.is_encrypted ? " · encrypted" : ""}`;

        meta.appendChild(left);
        meta.appendChild(chip);

        const preview = document.createElement("p");
        preview.className = "note-preview";
        preview.textContent = note.is_encrypted ? "[encrypted]" : note.content;

        const actions = document.createElement("div");
        actions.className = "btn-row";

        const viewBtn = document.createElement("button");
        viewBtn.className = "btn-secondary";
        viewBtn.textContent = "View";
        viewBtn.type = "button";
        viewBtn.onclick = () => selectNote(note.id);

        actions.appendChild(viewBtn);

        if (note.is_encrypted) {
          const decryptBtn = document.createElement("button");
          decryptBtn.className = "btn-secondary";
          decryptBtn.textContent = "Decrypt";
          decryptBtn.type = "button";
          decryptBtn.onclick = async () => {
            const input = document.createElement("input");
            input.type = "file";
            input.accept = ".txt";
            input.onchange = async () => {
              const file = input.files?.[0];
              if (!file) return;
              try {
                const text = await file.text();
                const key = text.trim();
                const payload = await notesRequest(`/notes/${note.id}?private_key=${encodeURIComponent(key)}`);
                state.selectedNote = payload;
                renderNotes();
                els.viewerEmpty.classList.add("hidden");
                els.viewerForm.classList.remove("hidden");
                els.viewerMeta.textContent = `Note #${payload.id} · owner ${payload.owner_id} · permission ${payload.permission}`;
                els.viewerContent.value = payload.content;
                els.viewerContent.disabled = true;
                els.saveBtn.disabled = true;
                const canDelete = payload.permission === "owner" || payload.permission === "admin";
                els.deleteBtn.disabled = !canDelete;
                els.shareUsername.disabled = !canDelete;
                els.sharePermission.disabled = !canDelete;
                els.shareBtn.disabled = !canDelete;
              } catch (error) {
                showStatus(error.message, "err");
              }
            };
            input.click();
          };
          actions.appendChild(decryptBtn);
        }

        if (note.can_edit && !note.is_encrypted) {
          const editBtn = document.createElement("button");
          editBtn.className = "btn-primary";
          editBtn.textContent = "Edit";
          editBtn.type = "button";
          editBtn.onclick = () => selectNote(note.id);
          actions.appendChild(editBtn);
        }

        item.appendChild(meta);
        item.appendChild(preview);
        item.appendChild(actions);
        els.noteList.appendChild(item);
      });
    }

    function renderFriends() {
      els.friendList.innerHTML = "";

      if (!state.friends.length) {
        const empty = document.createElement("p");
        empty.className = "mono";
        empty.textContent = "No friends yet. Add by username or email.";
        els.friendList.appendChild(empty);
        return;
      }

      state.friends.forEach((friend) => {
        const item = document.createElement("article");
        item.className = "note-item";

        const meta = document.createElement("div");
        meta.className = "note-meta";
        meta.textContent = friend.username;

        item.appendChild(meta);
        els.friendList.appendChild(item);
      });
    }

    function renderFriendOptions() {
      els.messageRecipient.innerHTML = '<option value="">Select a friend...</option>';
      els.shareFriend.innerHTML = '<option value="">Select a friend...</option>';

      if (!state.friends.length) return;

      state.friends.forEach((friend) => {
        const msgOption = document.createElement("option");
        msgOption.value = friend.username;
        msgOption.textContent = friend.username;
        els.messageRecipient.appendChild(msgOption);

        const shareOption = document.createElement("option");
        shareOption.value = friend.username;
        shareOption.textContent = friend.username;
        els.shareFriend.appendChild(shareOption);
      });
    }

    function handleSaveKey() {
      const value = els.keyValue.value.trim();
      if (!value) {
        showStatus("Key value is required.", "err");
        return;
      }
      const blob = new Blob([value], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "private-key.txt";
      a.click();
      URL.revokeObjectURL(url);
      els.keyValue.value = "";
      showStatus("Key file downloaded as private-key.txt");
    }

    function renderInvites() {
      els.inviteList.innerHTML = "";
      if (!state.invites.length) {
        const empty = document.createElement("p");
        empty.className = "mono";
        empty.textContent = "No pending invites.";
        els.inviteList.appendChild(empty);
        return;
      }

      state.invites.forEach((invite) => {
        const item = document.createElement("article");
        item.className = "note-item";

        const meta = document.createElement("div");
        meta.className = "note-meta";
        if (invite.direction === "incoming") {
          meta.textContent = `Incoming from ${invite.requester_username}`;
        } else {
          meta.textContent = `Outgoing to ${invite.recipient_username}`;
        }
        item.appendChild(meta);

        const sub = document.createElement("p");
        sub.className = "mono";
        sub.textContent = new Date(invite.created_at).toLocaleString();
        item.appendChild(sub);

        if (invite.direction === "incoming") {
          const actions = document.createElement("div");
          actions.className = "btn-row";

          const acceptBtn = document.createElement("button");
          acceptBtn.className = "btn-primary";
          acceptBtn.type = "button";
          acceptBtn.textContent = "Accept";
          acceptBtn.onclick = () => handleInviteAction(invite.request_id, "accept");

          const rejectBtn = document.createElement("button");
          rejectBtn.className = "btn-secondary";
          rejectBtn.type = "button";
          rejectBtn.textContent = "Reject";
          rejectBtn.onclick = () => handleInviteAction(invite.request_id, "reject");

          actions.appendChild(acceptBtn);
          actions.appendChild(rejectBtn);
          item.appendChild(actions);
        }

        els.inviteList.appendChild(item);
      });
    }

    function renderMessages() {
      els.messageList.innerHTML = "";

      if (!state.messages.length) {
        const empty = document.createElement("p");
        empty.className = "mono";
        empty.textContent = "No messages yet.";
        els.messageList.appendChild(empty);
        return;
      }

      state.messages.forEach((message) => {
        const item = document.createElement("article");
        item.className = `note-item msg-${message.direction}`;

        const meta = document.createElement("div");
        meta.className = "note-meta";
        const direction = message.direction === "sent" ? "to" : "from";
        const counterpart = message.direction === "sent"
          ? message.recipient_username
          : message.sender_username;
        meta.textContent = `${new Date(message.created_at).toLocaleString()} · ${direction} ${counterpart}${message.encrypted_with_private_key ? " · private-key" : ""}`;

        const content = document.createElement("p");
        content.className = "note-preview";
        const isEncryptedPlaceholder = message.encrypted_with_private_key && message.content.startsWith("[encrypted");
        content.textContent = isEncryptedPlaceholder ? "[encrypted]" : message.content;

        const actions = document.createElement("div");
        actions.className = "btn-row";

        if (message.encrypted_with_private_key && message.content.startsWith("[encrypted")) {
          const decryptBtn = document.createElement("button");
          decryptBtn.className = "btn-secondary";
          decryptBtn.textContent = "Decrypt";
          decryptBtn.type = "button";
          decryptBtn.addEventListener("click", async () => {
            const input = document.createElement("input");
            input.type = "file";
            input.accept = ".txt";
            input.onchange = async () => {
              const file = input.files?.[0];
              if (!file) return;
              try {
                const key = (await file.text()).trim();
                const query = `?private_key=${encodeURIComponent(key)}`;
                const payload = await notesRequest(`/messages${query}`);
                if (payload.messages) {
                  state.messages = payload.messages;
                  renderMessages();
                  showStatus("Messages decrypted with selected key");
                }
              } catch (error) {
                showStatus(error.message, "err");
              }
            };
            input.click();
          });
          actions.appendChild(decryptBtn);
        }

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "btn-danger";
        deleteBtn.textContent = "Delete";
        deleteBtn.type = "button";
        deleteBtn.addEventListener("click", async () => {
          if (!window.confirm("Delete this message?")) return;
          try {
            await notesRequest(`/messages/${message.id}`, { method: "DELETE" });
            showStatus("Message deleted");
            refreshMessages();
          } catch (error) {
            showStatus(error.message, "err");
          }
        });
        actions.appendChild(deleteBtn);

        item.appendChild(meta);
        item.appendChild(content);
        item.appendChild(actions);
        els.messageList.appendChild(item);
      });
    }

    async function refreshNotes() {
      try {
        const key = currentPrivateKey();
        const query = key ? `?private_key=${encodeURIComponent(key)}` : "";
        const payload = await notesRequest(`/notes${query}`);
        state.notes = Array.isArray(payload.notes) ? payload.notes : [];
        renderNotes();
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function refreshFriends() {
      try {
        const payload = await notesRequest("/friends");
        state.friends = Array.isArray(payload.friends) ? payload.friends : [];
        renderFriends();
        renderFriendOptions();
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function refreshInvites() {
      try {
        const payload = await notesRequest("/friends/invites");
        state.invites = Array.isArray(payload.invites) ? payload.invites : [];
        renderInvites();
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function refreshMessages() {
      try {
        const key = currentPrivateKey();
        const query = key ? `?private_key=${encodeURIComponent(key)}` : "";
        const payload = await notesRequest(`/messages${query}`);
        state.messages = Array.isArray(payload.messages) ? payload.messages : [];
        renderMessages();
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function selectNote(noteId) {
      try {
        const key = currentPrivateKey();
        const query = key ? `?private_key=${encodeURIComponent(key)}` : "";
        const note = await notesRequest(`/notes/${noteId}${query}`);
        state.selectedNote = note;
        renderNotes();

        els.viewerEmpty.classList.add("hidden");
        els.viewerForm.classList.remove("hidden");

        els.viewerMeta.textContent = `Note #${note.id} · owner ${note.owner_id} · permission ${note.permission}`;
        els.viewerContent.value = note.content;

        const canDelete = note.permission === "owner" || note.permission === "admin";
        const canShare = note.permission === "owner" || note.permission === "admin";

        if (note.is_encrypted) {
          els.viewerContent.disabled = true;
          els.saveBtn.disabled = true;
        } else {
          els.viewerContent.disabled = !note.can_edit;
          els.saveBtn.disabled = !note.can_edit;
        }
        els.deleteBtn.disabled = !canDelete;
        els.shareUsername.disabled = !canShare;
        els.sharePermission.disabled = !canShare;
        els.shareBtn.disabled = !canShare;
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleAuth(event) {
      event.preventDefault();

      const email = els.authEmail.value.trim().toLowerCase();
      const username = els.authUsername.value.trim().toLowerCase();
      const password = els.authPassword.value;
      const confirmPassword = els.authConfirmPassword.value;
      if (!email || !password) {
        showStatus("Email and password are required", "err");
        return;
      }

      try {
        if (state.mode === "register") {
          if (!username) {
            showStatus("Username is required for registration", "err");
            return;
          }

          const response = await authRequest("/register", { username, email, password, confirm_password: confirmPassword });
          if (response.verification_token) {
            els.verifyToken.value = response.verification_token;
            showStatus("Registration complete. Use token below to verify email.");
          } else {
            showStatus("Registration complete. Verify email.");
          }
          setAuthMode("login");
          return;
        }

        const payload = await authRequest("/login", { email, password });
        setSession(payload);
        updateLayout();
        await Promise.all([refreshNotes(), refreshFriends(), refreshInvites(), refreshMessages()]);
        showStatus("Logged in successfully");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleVerifyEmail() {
      const email = els.authEmail.value.trim().toLowerCase();
      const token = els.verifyToken.value.trim();
      if (!email || !token) {
        showStatus("Email and verification token are required", "err");
        return;
      }

      try {
        await authRequest("/verify-email", { email, token });
        showStatus("Email verified. You can login now.");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleResendToken() {
      const email = els.authEmail.value.trim().toLowerCase();
      if (!email) {
        showStatus("Email is required", "err");
        return;
      }

      try {
        const payload = await authRequest("/resend-verification", { email });
        if (payload.verification_token) {
          els.verifyToken.value = payload.verification_token;
        }
        showStatus("Verification token refreshed");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleForgotPassword() {
      const email = els.authEmail.value.trim().toLowerCase();
      if (!email) {
        showStatus("Email is required", "err");
        return;
      }

      try {
        await authRequest("/forgot-password", { email });
        els.resetPasswordSection.classList.remove("hidden");
        showStatus("If email exists, reset link has been sent");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleResetPassword() {
      const email = els.authEmail.value.trim().toLowerCase();
      const token = els.resetToken.value.trim();
      const newPassword = els.newPassword.value;
      const confirmNewPassword = els.confirmNewPassword.value;

      if (!email || !token || !newPassword || !confirmNewPassword) {
        showStatus("All fields are required", "err");
        return;
      }

      if (newPassword !== confirmNewPassword) {
        showStatus("Passwords do not match", "err");
        return;
      }

      try {
        await authRequest("/reset-password", {
          email,
          token,
          new_password: newPassword,
          confirm_password: confirmNewPassword
        });
        showStatus("Password reset. Please login.");
        els.resetPasswordSection.classList.add("hidden");
        els.resetToken.value = "";
        els.newPassword.value = "";
        els.confirmNewPassword.value = "";
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleCreate(event) {
      event.preventDefault();
      const content = els.createContent.value.trim();
      const privateKey = noteEncryptKey || currentPrivateKey();
      if (!content) {
        showStatus("Note content cannot be empty", "err");
        return;
      }

      try {
        await notesRequest("/notes", {
          method: "POST",
          body: JSON.stringify({
            content,
            private_key: privateKey || null
          })
        });

        els.createContent.value = "";
        noteEncryptKey = "";
        els.noteKeyFile.value = "";
        els.noteKeyLabel.classList.add("hidden");
        await refreshNotes();
        showStatus("Note created");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleSave(event) {
      event.preventDefault();
      if (!state.selectedNote) {
        return;
      }

      try {
        const privateKey = noteEncryptKey || currentPrivateKey();
        await notesRequest(`/notes/${state.selectedNote.id}`, {
          method: "PUT",
          body: JSON.stringify({
            content: els.viewerContent.value,
            private_key: privateKey || null
          })
        });

        showStatus("Note updated");
        await refreshNotes();
        await selectNote(state.selectedNote.id);
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleDelete() {
      if (!state.selectedNote) {
        return;
      }
      if (!window.confirm("Delete selected note?")) {
        return;
      }

      try {
        await notesRequest(`/notes/${state.selectedNote.id}`, { method: "DELETE" });
        showStatus("Note deleted");
        resetViewer();
        await refreshNotes();
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleShare() {
      if (!state.selectedNote) {
        return;
      }

      const recipient = els.shareFriend.value.trim().toLowerCase();
      if (!recipient) {
        showStatus("Select a friend to share with", "err");
        return;
      }

      try {
        await notesRequest("/notes/share", {
          method: "POST",
          body: JSON.stringify({
            note_id: state.selectedNote.id,
            recipient,
            permission: els.sharePermission.value
          })
        });

        showStatus("Note shared");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleAddFriend() {
      const identifier = els.friendIdentifier.value.trim().toLowerCase();
      if (!identifier) {
        showStatus("Friend username/email is required", "err");
        return;
      }

      try {
        await notesRequest("/friends", {
          method: "POST",
          body: JSON.stringify({ identifier })
        });

        els.friendIdentifier.value = "";
        await refreshInvites();
        showStatus("Invite sent");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleInviteAction(requestId, action) {
      try {
        await notesRequest(`/friends/invites/${requestId}/${action}`, { method: "POST" });
        await Promise.all([refreshInvites(), refreshFriends()]);
        renderFriendOptions();
        showStatus(action === "accept" ? "Invite accepted" : "Invite rejected");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    async function handleSendMessage() {
      const recipient = els.messageRecipient.value;
      const content = els.messageContent.value.trim();
      const privateKey = currentPrivateKey();

      if (!recipient) {
        showStatus("Select a friend first", "err");
        return;
      }
      if (!content) {
        showStatus("Message content cannot be empty", "err");
        return;
      }

      try {
        await notesRequest("/messages", {
          method: "POST",
          body: JSON.stringify({
            recipient,
            content,
            private_key: privateKey || null
          })
        });

        els.messageContent.value = "";
        await refreshMessages();
        showStatus("Message sent");
      } catch (error) {
        showStatus(error.message, "err");
      }
    }

    function syncPrivateKeyPathLabel(path) {
      els.privateKeyPath.textContent = path ? `Key file path: ${path}` : "No key file selected.";
    }

    async function handlePrivateKeyFileLoad() {
      const file = els.privateKeyFile.files?.[0];
      if (!file) {
        return;
      }

      try {
        const text = await file.text();
        const key = text.trim();
        els.globalPrivateKey.value = key;
        persistPrivateKey();

        const rawPath = els.privateKeyFile.value || file.name;
        sessionStorage.setItem("incognote_key_path", rawPath);
        syncPrivateKeyPathLabel(rawPath);
        showStatus("Private key loaded from file");

        await Promise.all([refreshNotes(), refreshMessages()]);
      } catch (error) {
        showStatus(error.message || "Failed to load key file", "err");
      }
    }

    function initializePrivateKeyState() {
      const rememberedKey = sessionStorage.getItem("incognote_private_key") || "";
      if (rememberedKey) {
        els.globalPrivateKey.value = rememberedKey;
      }
      const rememberedPath = sessionStorage.getItem("incognote_key_path") || "";
      syncPrivateKeyPathLabel(rememberedPath);
    }

    function logout() {
      clearSession();
      updateLayout();
      showStatus("Logged out");
    }

    async function loadAdminData() {
      if (state.role !== "admin") return;

      try {
        const usersPayload = await notesRequest("/admin/users");
        const userList = document.getElementById("admin-user-list");
        userList.innerHTML = "";

        if (!usersPayload.users || !usersPayload.users.length) {
          userList.innerHTML = "<p class='mono'>No users found.</p>";
          return;
        }

        usersPayload.users.forEach((u) => {
          const card = document.createElement("article");
          card.className = "note-item";
          card.innerHTML = `
            <div class="note-meta"><strong>#${u.id}</strong> ${u.username} (${u.email}) ${u.is_verified ? "" : "[not verified]"}</div>
            <div class="btn-row">
              <button class="btn-secondary" type="button">Show notes</button>
              <button class="btn-danger" type="button">Delete</button>
            </div>
            <div class="notes-box" style="display:none;margin-top:8px"></div>
          `;

          const notesBox = card.querySelector(".notes-box");
          const [notesBtn, deleteBtn] = card.querySelectorAll("button");

          notesBtn.addEventListener("click", async () => {
            if (notesBox.style.display === "block") {
              notesBox.style.display = "none";
              notesBtn.textContent = "Show notes";
              return;
            }
            try {
              const payload = await notesRequest(`/admin/users/${u.id}/notes`);
              notesBox.innerHTML = "";
              if (payload.notes && payload.notes.length) {
                payload.notes.forEach((n) => {
                  const ni = document.createElement("div");
                  ni.className = "note-item";
                  ni.style.marginBottom = "6px";
                  const preview = n.is_encrypted
                    ? "[encrypted]"
                    : n.content.substring(0, 100) + (n.content.length > 100 ? "..." : "");
                  ni.innerHTML = `<div class="note-meta">#${n.id} · ${n.is_encrypted ? "encrypted" : ""}</div><p class="note-preview">${preview}</p>`;
                  notesBox.appendChild(ni);
                });
              } else {
                notesBox.innerHTML = "<p class='mono'>No notes.</p>";
              }
              notesBox.style.display = "block";
              notesBtn.textContent = "Hide notes";
            } catch (error) {
              showStatus(error.message, "err");
            }
          });

          deleteBtn.addEventListener("click", async () => {
            if (!window.confirm(`Delete user #${u.id} (${u.username})? This will remove all their notes and data.`)) return;
            try {
              await notesRequest(`/admin/users/${u.id}`, { method: "DELETE" });
              showStatus(`User #${u.id} deleted`);
              loadAdminData();
            } catch (error) {
              showStatus(error.message, "err");
            }
          });

          userList.appendChild(card);
        });
      } catch (error) {
        console.error("Failed to load admin data:", error);
        showStatus("Failed to load admin data: " + error.message, "err");
      }
    }

    els.authForm.addEventListener("submit", handleAuth);
    els.authToggle.addEventListener("click", () => {
      setAuthMode(state.mode === "login" ? "register" : "login");
    });
    els.verifyEmailBtn.addEventListener("click", handleVerifyEmail);
    els.resendTokenBtn.addEventListener("click", handleResendToken);
    els.forgotPasswordBtn.addEventListener("click", handleForgotPassword);
    els.resetPasswordSubmitBtn.addEventListener("click", handleResetPassword);
    els.createForm.addEventListener("submit", handleCreate);
    els.viewerForm.addEventListener("submit", handleSave);
    els.deleteBtn.addEventListener("click", handleDelete);
    els.shareBtn.addEventListener("click", handleShare);
    els.refreshBtn.addEventListener("click", refreshNotes);
    els.addFriendBtn.addEventListener("click", handleAddFriend);
    els.refreshFriendsBtn.addEventListener("click", refreshFriends);
    els.refreshInvitesBtn.addEventListener("click", refreshInvites);
    els.sendMessageBtn.addEventListener("click", handleSendMessage);
    els.refreshMessagesBtn.addEventListener("click", refreshMessages);
    els.privateKeyFile.addEventListener("change", handlePrivateKeyFileLoad);
    els.globalPrivateKey.addEventListener("input", persistPrivateKey);
    els.logoutBtn.addEventListener("click", logout);
    els.navNotesBtn.addEventListener("click", () => switchTab("notes"));
    els.navFriendsBtn.addEventListener("click", () => switchTab("friends"));
    els.navMessagesBtn.addEventListener("click", () => switchTab("messages"));
    els.navKeysBtn.addEventListener("click", () => switchTab("keys"));
    els.navAdminBtn.addEventListener("click", () => switchTab("admin"));
    els.saveKeyBtn.addEventListener("click", handleSaveKey);
    els.noteEncryptBtn.addEventListener("click", () => els.noteKeyFile.click());
    els.noteKeyFile.addEventListener("change", async () => {
      const file = els.noteKeyFile.files?.[0];
      if (!file) return;
      try {
        noteEncryptKey = (await file.text()).trim();
        els.noteKeyLabel.textContent = `Key: ${file.name}`;
        els.noteKeyLabel.classList.remove("hidden");
      } catch (error) {
        showStatus(error.message, "err");
      }
    });

    switchTab("notes");

    setAuthMode("login");
    initializePrivateKeyState();
    updateLayout();
    if (state.token) {
      Promise.all([refreshNotes(), refreshFriends(), refreshInvites(), refreshMessages()]).catch(() => {
        showStatus("Could not load notes. Check services status.", "err");
      });
    }
