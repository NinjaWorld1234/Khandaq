import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Khandaq SOC Dashboard",
  description: "Next-Gen Agentic SOC Interface",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
