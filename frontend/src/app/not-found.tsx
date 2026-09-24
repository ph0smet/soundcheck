import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-[70dvh] items-center justify-center p-6">
      <div className="max-w-sm text-center">
        <p className="font-mono text-[13px] font-semibold uppercase tracking-[0.06em] text-unknown">Unknown</p>
        <h1 className="mt-2 text-[20px] font-semibold tracking-[-0.02em]">This page is outside the modeled fragment</h1>
        <p className="mt-2 text-[13px] text-ink-2">The address does not match any route.</p>
        <Link
          href="/verify"
          className="mt-5 inline-flex h-8 items-center rounded-md bg-inverse px-3 text-[13px] font-medium text-on-inverse"
        >
          Back to Verify
        </Link>
      </div>
    </div>
  );
}
