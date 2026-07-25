/** Avatar — User avatar with fallback initials. */
interface AvatarProps { name?: string; src?: string; size?: "sm" | "md" | "lg"; }
const sizeMap = { sm: "w-8 h-8 text-xs", md: "w-10 h-10 text-sm", lg: "w-14 h-14 text-lg" };
export default function Avatar({ name, src, size = "md" }: AvatarProps) {
  const initials = name?.split(" ").map((n) => n[0]).join("").slice(0, 2).toUpperCase() || "?";
  if (src) return <img src={src} alt={name} className={`${sizeMap[size]} rounded-full object-cover`} />;
  return <div className={`${sizeMap[size]} rounded-full bg-cerberus-blue/20 border border-cerberus-blue/40 flex items-center justify-center text-cerberus-blue font-bold`}>{initials}</div>;
}
