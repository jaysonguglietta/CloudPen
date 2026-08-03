import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { configuredOrigin } from "../lib/security/runtime";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export async function generateMetadata(): Promise<Metadata> {
  const origin = configuredOrigin();
  const socialImage = `${origin}/og.png`;
  const title = "CloudPen — Cloud Attack Path Validation";
  const description = "Safely prove exploitable cloud identity paths, capture evidence, and verify remediation.";

  return {
    metadataBase: new URL(origin),
    title,
    description,
    openGraph: {
      title,
      description,
      type: "website",
      images: [{ url: socialImage, width: 1732, height: 909, alt: "CloudPen — Prove the path. Close the exposure." }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [socialImage],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
