<script>
  // The OpenInstall mark, inlined so it inherits `currentColor` and themes
  // cleanly in light/dark. Source: openinstall_logo.svg.
  let { size = 24 } = $props();
  const w = $derived(Math.round((size * 707) / 746));
</script>

<svg
  viewBox="0 0 707 746"
  width={w}
  height={size}
  fill="currentColor"
  fill-rule="evenodd"
  aria-hidden="true"
  role="img"
>
  <path
    d="M 0 190 L 0 544 L 346 742 L 368 742 L 706 544 L 706 190 L 531 92 L 507 89 L 451 128 L 632 231 L 604 251 L 604 494 L 356 647 L 98 491 L 98 248 L 74 231 L 254 121 L 183 88 Z M 311 0 L 311 358 L 282 333 L 184 333 L 354 502 L 522 333 L 424 333 L 395 359 L 395 0 Z"
  />
</svg>
