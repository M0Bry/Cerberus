/**
 * useUserProfile — Fetch + update user profile.
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { userApi } from "../api/userApi";

export function useUserProfile() {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["userProfile"], queryFn: () => userApi.getProfile().then((r) => r.data) });
  const updateMutation = useMutation({
    mutationFn: (data: any) => userApi.updateProfile(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["userProfile"] }),
  });
  return { ...query, updateProfile: updateMutation };
}
