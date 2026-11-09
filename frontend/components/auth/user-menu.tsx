"use client";

import {
  CircleUser,
  FolderGit2,
  Globe,
  LayoutDashboard,
  LogOut,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuth } from "@/components/auth/auth-provider";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { isAuthConfigured, signOut } from "@/lib/supabase";

function signInHref(pathname: string): string {
  // The home page has nothing to come back to, so those visitors get the dashboard.
  const hasNoReturnPath =
    pathname === "/" || pathname === "/login" || pathname.startsWith("/auth/");
  return hasNoReturnPath
    ? "/login"
    : `/login?next=${encodeURIComponent(pathname)}`;
}

export function UserMenu() {
  const { user, loading } = useAuth();
  const pathname = usePathname();

  if (!isAuthConfigured || loading) return null;

  if (!user) {
    return (
      <Link
        href={signInHref(pathname)}
        className={buttonVariants({ variant: "ghost", size: "sm" })}
      >
        Sign in
      </Link>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="ghost" size="icon" aria-label="Account menu" />
        }
      >
        <CircleUser aria-hidden />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="truncate">
            {user.email ?? "Signed in"}
          </DropdownMenuLabel>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem render={<Link href="/dashboard" />}>
          <LayoutDashboard aria-hidden />
          Dashboard
        </DropdownMenuItem>
        <DropdownMenuItem render={<Link href="/domains" />}>
          <Globe aria-hidden />
          My domains
        </DropdownMenuItem>
        <DropdownMenuItem render={<Link href="/repositories" />}>
          <FolderGit2 aria-hidden />
          Repositories
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => void signOut()}>
          <LogOut aria-hidden />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
