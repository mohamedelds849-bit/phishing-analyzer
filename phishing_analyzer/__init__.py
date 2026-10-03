"""phishing-analyzer - offline SOC Level-1 triage of suspicious .eml files.

The analyzer only *reads* the message: attachments are hashed and statically
inspected (file name, magic bytes, ZIP directory listing) but never executed,
opened by an application, or written to disk.
"""

__version__ = "1.0.0"
