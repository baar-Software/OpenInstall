import { test } from "node:test";
import assert from "node:assert/strict";

import { repoSourceFromLink } from "./url.js";

test("repoSourceFromLink parses query form", () => {
  assert.equal(
    repoSourceFromLink(
      "openinstall://repo?url=https%3A%2F%2Fexample.com%2Fopeninstall",
    ),
    "https://example.com/openinstall",
  );
});

test("repoSourceFromLink parses path shorthand", () => {
  assert.equal(
    repoSourceFromLink("openinstall://repo/example.com/openinstall"),
    "https://example.com/openinstall",
  );
});

test("repoSourceFromLink ignores install links", () => {
  assert.equal(repoSourceFromLink("openinstall://com.example.app"), null);
  assert.equal(repoSourceFromLink("openinstall://example.com/app.oip"), null);
});
