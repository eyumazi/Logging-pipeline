(function () {
    "use strict";

    var state = { events: [] };
    var elements = {
        connection: document.getElementById("connection-status"),
        refresh: document.getElementById("refresh-button"),
        search: document.getElementById("search-input"),
        table: document.getElementById("event-table"),
        error: document.getElementById("error-message"),
        updated: document.getElementById("last-updated"),
        events: document.getElementById("event-count"),
        high: document.getElementById("high-count"),
        windows: document.getElementById("windows-count"),
        linux: document.getElementById("linux-count")
    };

    function escapeHtml(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function eventMessage(event) {
        return event.message || event._msg || event.log || event.msg || "(no message)";
    }

    function eventTime(event) {
        return event.normalized_at || event._time || event.time || event.timestamp || "";
    }

    function severity(event) {
        return String(event.severity || event.level || "info").toLowerCase();
    }

    function formatTime(value) {
        if (!value) return "—";
        var date = new Date(value);
        return isNaN(date.getTime()) ? String(value) : date.toLocaleString();
    }

    function parseResponse(text) {
        return text.trim().split(/\r?\n/).filter(Boolean).map(function (line) {
            try { return JSON.parse(line); } catch (error) { return null; }
        }).filter(Boolean);
    }

    function setConnection(connected) {
        elements.connection.textContent = connected ? "VictoriaLogs connected" : "VictoriaLogs unavailable";
        elements.connection.className = connected ? "status status-ok" : "status status-error";
    }

    function renderMetrics(events) {
        elements.events.textContent = events.length;
        elements.high.textContent = events.filter(function (event) {
            return severity(event) === "critical" || severity(event) === "high";
        }).length;
        elements.windows.textContent = events.filter(function (event) {
            return String(event.os_type || "").toLowerCase() === "windows";
        }).length;
        elements.linux.textContent = events.filter(function (event) {
            return String(event.os_type || "").toLowerCase() === "linux";
        }).length;
    }

    function renderTable() {
        var query = elements.search.value.trim().toLowerCase();
        var events = state.events.filter(function (event) {
            return !query || JSON.stringify(event).toLowerCase().indexOf(query) !== -1;
        });

        if (!events.length) {
            elements.table.innerHTML = '<tr><td class="empty" colspan="5">No matching events</td></tr>';
            return;
        }

        elements.table.innerHTML = events.map(function (event) {
            var level = severity(event);
            return "<tr>" +
                "<td>" + escapeHtml(formatTime(eventTime(event))) + "</td>" +
                '<td><span class="severity severity-' + escapeHtml(level) + '">' + escapeHtml(level) + "</span></td>" +
                "<td>" + escapeHtml(event.log_source || event.source || "—") + "</td>" +
                "<td>" + escapeHtml(event.host || event.hostname || "—") + "</td>" +
                "<td class=\"message\">" + escapeHtml(eventMessage(event)) + "</td>" +
                "</tr>";
        }).join("");
    }

    function loadEvents() {
        elements.refresh.disabled = true;
        elements.error.hidden = true;
        elements.connection.textContent = "Refreshing";
        elements.connection.className = "status status-loading";

        return fetch("/api/select/logsql/query?query=*&limit=100", { headers: { Accept: "application/x-ndjson" } })
            .then(function (response) {
                if (!response.ok) throw new Error("VictoriaLogs returned HTTP " + response.status);
                return response.text();
            })
            .then(function (text) {
                state.events = parseResponse(text);
                renderMetrics(state.events);
                renderTable();
                elements.updated.textContent = "Updated " + new Date().toLocaleTimeString();
                setConnection(true);
            })
            .catch(function (error) {
                state.events = [];
                renderMetrics(state.events);
                renderTable();
                elements.error.textContent = "Unable to load events: " + error.message;
                elements.error.hidden = false;
                setConnection(false);
            })
            .finally(function () {
                elements.refresh.disabled = false;
            });
    }

    elements.refresh.addEventListener("click", loadEvents);
    elements.search.addEventListener("input", renderTable);
    loadEvents();
}());
