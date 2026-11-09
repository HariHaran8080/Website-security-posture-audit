import React from 'react';

const CHECKS = [
  {
    num: "01",
    title: "Security headers",
    description: "Evaluates whether your web server instructs modern browsers to block clickjacking, code injection, and cleartext downgrades.",
    tags: "CSP · HSTS · X-Frame-Options · X-Content-Type · Referrer · Permissions"
  },
  {
    num: "02",
    title: "TLS certificate",
    description: "Verifies your SSL/TLS encryption certificate expiration, trust chain issuer, and ensures deprecated protocols like TLS 1.0 and 1.1 are rejected.",
    tags: "Expiry · Issuer · Protocol version · Weak ciphers"
  },
  {
    num: "03",
    title: "Cookie flags",
    description: "Audits session cookies to ensure they cannot be accessed by rogue client scripts or transmitted over unencrypted HTTP connections.",
    tags: "Secure · HttpOnly · SameSite (Lax/Strict)"
  },
  {
    num: "04",
    title: "Exposed files",
    description: "Scans for accidentally published sensitive files that leak credentials, source code histories, or server administration panels.",
    tags: "/.git/HEAD · /.env · /backup.zip · /phpinfo.php · /admin"
  },
  {
    num: "05",
    title: "CORS policy",
    description: "Tests whether your cross-origin resource sharing policy accidentally reflects untrusted origins while sending authenticated credentials.",
    tags: "Wildcard origin · Reflected origin · Access credentials"
  },
  {
    num: "06",
    title: "Open ports",
    description: "Probes the top twenty TCP network ports to detect unencrypted remote management tools and databases exposed directly to the public internet.",
    tags: "FTP (21) · SSH (22) · Telnet (23) · MySQL (3306) · RDP (3389)"
  }
];

export default function ChecksSection() {
  return (
    <section id="checks" className="py-24 border-t border-line">
      <div className="content-wrapper">
        {/* Section Header */}
        <div className="max-w-2xl mb-14">
          <div className="font-mono text-xs uppercase tracking-widest text-subtle mb-3">
            What it checks
          </div>
          <h2 className="font-heading font-semibold text-3xl sm:text-4xl text-ink tracking-tight mb-4">
            Six checks, one clear grade.
          </h2>
          <p className="text-muted text-[17px] leading-[1.6]">
            Every scan inspects six critical attack surfaces without executing destructive exploits or taking services offline.
          </p>
        </div>

        {/* 3-column grid (2 on tablet, 1 on mobile) with NO card backgrounds */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-10 gap-y-12">
          {CHECKS.map((check) => (
            <div 
              key={check.num} 
              className="border-t border-ink pt-5 flex flex-col justify-between"
            >
              <div>
                <div className="font-mono text-xs font-medium text-subtle tracking-wider mb-2">
                  {check.num}
                </div>
                <h3 className="font-heading font-bold text-xl text-ink mb-2.5">
                  {check.title}
                </h3>
                <p className="text-muted text-[15px] leading-relaxed mb-6">
                  {check.description}
                </p>
              </div>

              <div className="font-mono text-xs text-subtle border-t border-line pt-3">
                {check.tags}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

