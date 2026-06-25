import { test } from "node:test";
import assert from "node:assert/strict";

import { canInstall, requiresOverride, trustRequiresOverride } from "./consent.js";

test("Verified -> true", () => {
  assert.equal(canInstall({ trust: "Verified" }), true);
});

test("VerifiedNewPublisher -> true", () => {
  assert.equal(canInstall({ trust: "VerifiedNewPublisher" }), true);
});

test("Unverified -> true", () => {
  assert.equal(canInstall({ trust: "Unverified" }), true);
});

test("PublisherChanged requires override", () => {
  assert.equal(canInstall({ trust: "PublisherChanged", overridden: false }), false);
  assert.equal(canInstall({ trust: "PublisherChanged", overridden: true }), true);
});

test("fails closed on unknown trust string", () => {
  assert.equal(canInstall({ trust: "" }), false);
  assert.equal(canInstall({ trust: "Bogus" }), false);
  assert.equal(canInstall({ trust: "Bogus", overridden: true }), true);
});

test("trustRequiresOverride: only PublisherChanged", () => {
  assert.equal(trustRequiresOverride("PublisherChanged"), true);
  assert.equal(trustRequiresOverride("Verified"), false);
  assert.equal(trustRequiresOverride("VerifiedNewPublisher"), false);
  assert.equal(trustRequiresOverride("Unverified"), false);
});

test("requiresOverride is only for publisher key changes", () => {
  assert.equal(requiresOverride({ trust: "Verified" }), false);
  assert.equal(requiresOverride({ trust: "PublisherChanged" }), true);
});
