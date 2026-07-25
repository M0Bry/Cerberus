/**
 * SocialReconCard — Social media reconnaissance results.
 */

import Card from "../ui/Card";
import Badge from "../ui/Badge";

interface SocialProfile {
  platform: string;
  url: string;
  exists: boolean;
  category: string;
  importance: string;
}

const CATEGORY_INDICATORS: Record<string, string> = {
  social_media: "circle",
  development: "square",
  professional: "diamond",
};

export default function SocialReconCard({ profiles }: { profiles: SocialProfile[] }) {
  const found = profiles.filter((p) => p.exists);

  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Social Media Reconnaissance ({found.length} found)
      </h3>

      {found.length === 0 ? (
        <p className="text-gray-500 text-sm">No social media profiles discovered.</p>
      ) : (
        <div className="space-y-2">
          {found.map((profile, i) => (
            <div
              key={i}
              className="flex items-center justify-between p-2 bg-cerberus-gray-900 rounded-lg"
            >
              <div className="flex items-center gap-3">
                <span className="text-lg" aria-hidden>
                  {CATEGORY_INDICATORS[profile.category] || "link"}
                </span>
                <div>
                  <p className="text-sm text-white font-medium">{profile.platform}</p>
                  <a
                    href={profile.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-cerberus-blue hover:underline"
                  >
                    {profile.url}
                  </a>
                </div>
              </div>
              <Badge
                variant={
                  profile.importance === "high"
                    ? "danger"
                    : profile.importance === "medium"
                    ? "warning"
                    : "default"
                }
              >
                {profile.importance}
              </Badge>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
