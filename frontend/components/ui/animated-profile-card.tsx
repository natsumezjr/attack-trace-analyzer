"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/card/card2";
import { cn } from "@/lib/utils";
import { useGSAP } from "@gsap/react";
import { gsap } from "gsap";
import { useTheme } from "next-themes";
import * as React from "react";
import { useRef } from "react";

export interface SocialLink {
  id: string;
  url: string;
  icon: React.ReactNode;
  label: string;
}

export interface ProfileCardContentProps
  extends React.HTMLAttributes<HTMLDivElement> {
  /** The full name of the individual. */
  name: string;
  /** The location, such as city and state. */
  location: string;
  /** A short biography or description. */
  bio: string;
  /**
   * The color variant of the card content. Use 'on-accent' for text
   * that needs to be readable on a background matching the accent color.
   * @default 'default'
   */
  variant?: "default" | "on-accent";
  /** An array of social media links to display in the footer. */
  socials?: SocialLink[];
  /** Optional inline styles for the main title element. */
  titleStyle?: React.CSSProperties;
  /** Optional inline styles for the root Card element. */
  cardStyle?: React.CSSProperties;
  /** Custom Tailwind classes for the location description text. */
  descriptionClassName?: string;
  /** Custom Tailwind classes for the main biography paragraph. */
  bioClassName?: string;
  /** Custom Tailwind classes for the footer container. */
  footerClassName?: string;
}

/**
 * A presentational component that displays the content of a user profile card.
 * It is designed to be composed within other components, such as an animation container.
 */
export const ProfileCardContent = React.forwardRef<
  HTMLDivElement,
  ProfileCardContentProps
>(
  (
    {
      className,
      name,
      location,
      bio,
      variant = "default",
      socials = [],
      titleStyle,
      cardStyle,
      descriptionClassName,
      bioClassName,
      footerClassName,
      ...props
    },
    ref
  ) => {
    const isOnAccent = variant === "on-accent";

    return (
      <Card
        ref={ref}
        className={cn(
          "flex h-full w-full flex-col rounded-3xl border-0 px-8 py-5",
          isOnAccent
            ? "text-[var(--on-accent-foreground)]"
            : "bg-card text-card-foreground",
          className
        )}
        style={cardStyle}
        {...props}
      >
        <CardHeader className="p-0">
          <CardDescription
            className={cn(
              "pt-6 text-left",
              !isOnAccent && "text-muted-foreground",
              descriptionClassName
            )}
            style={
              isOnAccent ? { color: "var(--on-accent-muted-foreground)" } : {}
            }
          >
            {location}
          </CardDescription>
          <CardTitle
            className={cn("text-2xl text-left", className)}
            style={{
              ...(isOnAccent ? { color: "var(--on-accent-foreground)" } : {}),
              ...titleStyle,
            }}
          >
            {name}
          </CardTitle>
        </CardHeader>

        <CardContent className="mt-3 flex-grow p-0">
          <p
            className={cn(
              "text-base leading-relaxed text-left",
              !isOnAccent && "text-foreground/80",
              bioClassName
            )}
            style={isOnAccent ? { opacity: 0.9 } : {}}
          >
            {bio}
          </p>
        </CardContent>

        {socials.length > 0 && (
          <CardFooter className={cn("mt-3 p-0", footerClassName)}>
            <div
              className={cn(
                "flex items-center gap-4",
                !isOnAccent && "text-muted-foreground"
              )}
              style={
                isOnAccent ? { color: "var(--on-accent-muted-foreground)" } : {}
              }
            >
              {socials.map((social) => (
                <a
                  key={social.id}
                  href={social.url}
                  aria-label={social.label}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    "transition-opacity",
                    isOnAccent ? "hover:opacity-75" : "hover:text-foreground"
                  )}
                >
                  {social.icon}
                </a>
              ))}
            </div>
          </CardFooter>
        )}
      </Card>
    );
  }
);
ProfileCardContent.displayName = "ProfileCardContent";

export interface AnimatedProfileCardProps
  extends React.HTMLAttributes<HTMLDivElement> {
  /** The React node to display as the base layer of the card. */
  baseCard: React.ReactNode;
  /** The React node to display as the overlay layer, revealed on hover. */
  overlayCard: React.ReactNode;
  /**
   * The accent color used for the border and avatar ring.
   * Accepts any valid CSS color value.
   */
  accentColor?: string;
  /**
   * The color for primary text when on the accent background.
   * @default '#ffffff'
   */
  onAccentForegroundColor?: string;
  /**
   * The color for secondary/muted text when on the accent background.
   * @default 'rgba(255, 255, 255, 0.8)'
   */
  onAccentMutedForegroundColor?: string;
}

/**
 * A container component that creates a circular reveal animation on hover.
 * It composes two child components, a `baseCard` and an `overlayCard`,
 * to create the effect.
 */
export const AnimatedProfileCard = React.forwardRef<
  HTMLDivElement,
  AnimatedProfileCardProps
>(
  (
    {
      className,
      accentColor = "color-mix(in oklch, var(--foreground) 85%, var(--background))",
      onAccentForegroundColor = "var(--background)",
      onAccentMutedForegroundColor = "color-mix(in oklch, var(--background) 80%, transparent)",
      baseCard,
      overlayCard,
      ...props
    },
    ref
  ) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const overlayRef = useRef<HTMLDivElement>(null);
    const { resolvedTheme } = useTheme();
    const [mounted, setMounted] = React.useState(false);
    const overlayThemeClass =
      mounted && resolvedTheme === "dark" ? "light" : "dark";

    React.useEffect(() => {
      setMounted(true);
    }, []);

    const setContainerRef = React.useCallback(
      (node: HTMLDivElement | null) => {
        containerRef.current = node;
        if (typeof ref === "function") {
          ref(node);
        } else if (ref) {
          (ref as React.MutableRefObject<HTMLDivElement | null>).current = node;
        }
      },
      [ref]
    );

    const initialClipPath = "circle(0% at 20% 20%)";
    const hoverClipPath = "circle(150% at 20% 20%)";

    useGSAP(
      () => {
        gsap.set(overlayRef.current, { clipPath: initialClipPath });
      },
      { scope: containerRef }
    );
    const handleMouseEnter = () => {
      gsap.killTweensOf(overlayRef.current);
      gsap.to(overlayRef.current, {
        clipPath: hoverClipPath,
        duration: 0.4,
        ease: "expo.inOut",
      });
    };
    const handleMouseLeave = () => {
      gsap.killTweensOf(overlayRef.current);
      gsap.to(overlayRef.current, {
        clipPath: initialClipPath,
        duration: 0.6,
        ease: "expo.out(1, 1)",
      });
    };

    return (
      <div
        ref={setContainerRef}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        style={
          {
            "--accent-color": accentColor,
            "--on-accent-foreground": onAccentForegroundColor,
            "--on-accent-muted-foreground": onAccentMutedForegroundColor,
            borderColor: "var(--accent-color)",
          } as React.CSSProperties
        }
        className={cn(
          "relative h-fit w-[320px] overflow-hidden rounded-3xl border-2",
          className
        )}
        {...props}
      >
        <div className="h-full w-full">{baseCard}</div>
        <div
          ref={overlayRef}
          className={cn("absolute inset-0 h-full w-full", overlayThemeClass)}
        >
          {overlayCard}
        </div>
      </div>
    );
  }
);
AnimatedProfileCard.displayName = "AnimatedProfileCard";
