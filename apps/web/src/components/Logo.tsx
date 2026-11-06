export function Logo({ size = 24 }: { size?: number }) {
  return (
    <div
      className="flex items-center justify-center bg-accent"
      style={{ width: size, height: size, borderRadius: size * 0.29 }}
    >
      <svg
        aria-hidden="true"
        width={size * 0.58}
        height={size * 0.58}
        viewBox="0 0 24 24"
        fill="none"
        stroke="#FFFFFF"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M9 17H7A5 5 0 0 1 7 7h2" />
        <path d="M15 7h2a5 5 0 0 1 0 10h-2" />
        <path d="M8 12h8" />
      </svg>
    </div>
  );
}
