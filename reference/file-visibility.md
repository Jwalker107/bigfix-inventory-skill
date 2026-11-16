# File visibility: scan scope, exclusions and the file cache

A signature cannot match a file the scanner cannot see. Before changing a signature that
"doesn't find" something, check this page: the usual cause is scan scope, an exclusion, or a
stale cache, not the signature body.

`FindFilePathEx` and `FindFilePath` search a **prepared file-system cache**. They never walk
the disk themselves and never bypass the cache. Which cache, and how it is built and
refreshed, depends on the platform and configuration.

## The two cache paths

| Path | Where it is used | How file metadata gets there |
| --- | --- | --- |
| **Scanner Service / FSMon** | Windows, normal deployed path | `bf-scanner` maintains a reusable cache in the background, periodically updating directory, file, path and size metadata. Directories in the FSMon exclusion list are invisible to file searches, including the default exclusions. |
| **Provider Cache 2** | All other supported CIT platforms; on Windows a fallback and the standalone test path | Built **on demand from the catalog passed to `wscansw`**: a file name that no signature in that catalog searches for is not cached. `maxDataAge="0"` forces a rebuild on every run. After the file system changes, after the catalog adds a search name, or after the scan configuration changes, run `wscanfs -reset` and scan again. |

Consequences for an author:

- **A name the catalog never searches for is never cached** under Provider Cache 2. This is the
  standalone-harness equivalent of "missing from the `FileMask` list": the harnesses in
  [testing.md](testing.md) build their `FileMask` list from the signatures' own
  `FindFilePathEx` names for exactly this reason.
- **Exclusions are configured in two different places** and do not share a list:
  FSMon exclusions belong to the Windows Scanner Service configuration; Provider Cache 2
  exclusions belong to the scan configuration passed with `wscansw -c`.
- **Reuse the cache while tuning a signature.** Rebuilds are slow (a `C:\` walk takes about
  45 s on a test host). Reset only when the file system or the set of searched names changed.
- `FileExists`, `ReadFile` and `FileInfoCompare` take a path and do **not** need the cache or a
  cached name; they also cannot locate or enumerate files. They still cannot read past endpoint
  permissions or applicable scan configuration restrictions.

## Windows: selecting and configuring the provider

Provider selection is global:

```bat
wscancfg.exe -s fscanner.provider provider_bfscanner   :: Scanner Service (FSMon) - normal
wscancfg.exe -s fscanner.provider provider_cache2      :: Provider Cache 2 - fallback / testing
```

Use Provider Cache 2 when investigating a Scanner Service provider problem, or when signature
testing should wait for a catalog-scoped cache to be built.

FSMon exclusions are managed through the service, **not** through a Provider Cache 2 test XML:

```bat
bf-scanner.exe config add FSMon.ExcludeDirectories <directory>
bf-scanner.exe config remove FSMon.ExcludeDirectories <directory>
bf-scanner.exe service restart
```

Allow time for the cache to refresh before testing again.

## Standalone Provider Cache 2 test configurations

These `FSScanner` plugin configurations are for standalone `wscansw` runs that pass the
configuration with `-c`. They set the **test's** scan scope and exclusions. They do not
configure the Windows Scanner Service's FSMon cache, and they are not a production scan
configuration - a real BigFix Inventory deployment writes its own.

On Windows, the `FSScan` element used by `wscanfs` must exclude the same directories as the
`FSScanner` plugin in the same file, or `wscansw` discards the cached `C:\` tree and every
`FindFilePathEx` returns nothing (see [testing.md](testing.md#windows)).

Windows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<IBM>
<CIT>
<XSE priority="low" version="1.0">
<Plugins>
<Plugin name="FSScanner">
<Attribute name="includeDirectory" value="$local::*"/>

<Attribute name="excludeDirectory" value="?:/System Volume Information/*"/>
<Attribute name="excludeDirectory" value="?:/$Recycle.Bin/*"/>
<Attribute name="excludeDirectory" value="?:/RECYCLER/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/System32/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/SysWOW64/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/winsxs/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/ServicePackFiles/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/installer/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/$NtUninstall/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/$NtServicePackUninstall*$/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/$hf_mig$/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/servicing/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/SoftwareDistribution/*"/>
<Attribute name="excludeDirectory" value="*/Windows.old/*"/>
<Attribute name="excludeDirectory" value="?:/$WINDOWS.~BT/*"/>
<Attribute name="excludeDirectory" value="?:/Windows/servicing/*"/>
<Attribute name="excludeDirectory" value="?:/ProgramData/Docker/windowsfilter/*"/>
<Attribute name="excludeDirectory" value="?:/ProgramData/Package Cache/*"/>
<Attribute name="excludeDirectory" value="*/tmp/*"/>
<Attribute name="excludeDirectory" value="*/temp/*"/>
<Attribute name="excludeDirectory" value="*/cache/out-of-date/*"/>
<Attribute name="excludeDirectory" value="*/Temporary Internet Files/*"/>

<Attribute name="excludeGuestDirectories" value="true"/>
<Attribute name="maxDataAge" value="7200"/>
<Attribute name="provider" value="provider_cache2"/>
<Attribute name="maxQueryTime" value="43200"/>
<Attribute name="interruptOnTimeout" value="true"/>
<Attribute name="assumeAutoFS" value="remote"/>
<Attribute name="extensionToCache" value="*.exe"/>
<Attribute name="extensionToCache" value="*.sys"/>
<Attribute name="extensionToCache" value="*.com"/>
<Attribute name="extensionToCache" value="*.ear"/>
<Attribute name="extensionToCache" value="*.ocx"/>
<Attribute name="extensionToCache" value="*.swidtag"/>
<Attribute name="extensionToCache" value="*.slmtag"/>
<Attribute name="extensionToCache" value="*.gguf"/>
<Attribute name="extensionToCache" value="*.safetensors"/>
<Attribute name="extensionToCache" value="*.GGUF"/>
<Attribute name="extensionToCache" value="*.SAFETENSORS"/>
</Plugin>
</Plugins>
</XSE>
</CIT>
</IBM>
```

Linux:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<IBM>
<CIT>
<XSE version="1.0">
<Plugins>
<Plugin name="FSScanner">
<Attribute name="includeDirectory" value="$local::*"/>

<Attribute name="excludeDirectory" value="/proc/*"/>
<Attribute name="excludeDirectory" value="*/tmp/*"/>
<Attribute name="excludeDirectory" value="*/eznim/*"/>
<Attribute name="excludeDirectory" value="*/unicore/lib/*"/>
<Attribute name="excludeDirectory" value="*/perl/lib/*"/>
<Attribute name="excludeDirectory" value="*/perl5/*"/>
<Attribute name="excludeDirectory" value="/usr/src/kernels/*"/>

<Attribute name="excludeDirectory" value="/var/opt/BESClient/LMT/CIT/docker/images/*"/>
<Attribute name="excludeDirectory" value="*/work/docker_scan/images/*"/>
<Attribute name="excludeDirectory" value="/var/lib/docker/*"/>
<Attribute name="excludeDirectory" value="/var/lib/containers*"/>
<Attribute name="excludeGuestDirectories" value="true"/>
<Attribute name="extensionToCache" value="*.sh"/>
<Attribute name="extensionToCache" value="*.bin"/>
<Attribute name="extensionToCache" value="*.pl"/>
<Attribute name="extensionToCache" value="*.ear"/>
<Attribute name="extensionToCache" value="*.SH"/>
<Attribute name="extensionToCache" value="*.BIN"/>
<Attribute name="extensionToCache" value="*.PL"/>
<Attribute name="extensionToCache" value="*.EAR"/>
<Attribute name="extensionToCache" value="*.swidtag"/>
<Attribute name="extensionToCache" value="*.slmtag"/>
<Attribute name="extensionToCache" value="*.gguf"/>
<Attribute name="extensionToCache" value="*.safetensors"/>
<Attribute name="extensionToCache" value="*.GGUF"/>
<Attribute name="extensionToCache" value="*.SAFETENSORS"/>
<Attribute name="maxDataAge" value="7200"/>
<Attribute name="provider" value="provider_cache2"/>
<Attribute name="maxQueryTime" value="43200"/>
<Attribute name="interruptOnTimeout" value="true"/>
<Attribute name="assumeAutoFS" value="remote"/>
</Plugin>
</Plugins>
</XSE>
</CIT>
</IBM>
```

Note what the default exclusions imply for a signature: anything under a temp directory, the
Windows servicing/installer trees, container image stores or guest directories is invisible by
default, so don't base detection on evidence that only exists there.

## macOS

macOS has **no FileSystem Scan and no extended-signature evaluation engine**. The BigFix
Scanner Service on macOS runs only the `bf-scanner` service (commands `config`, `dex`,
`export hwinventory`, `run`, `service`, `upgrade`; checked 11.0.43.1). Extended signatures do
not run on macOS endpoints at all. macOS-layout paths can only be exercised by planting the
files in a Linux container, which tests the expression, not macOS detection. Whether BigFix
Inventory identifies macOS software by another mechanism was not checked *(not verified)*.

## HCL references

- [Manual scan configuration](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/planinconf/c_manual_scan_configuration.html)
- [Windows File System Monitoring Cache](https://help.hcl-software.com/bigfix/11.0/BigFix_Scanner/BigFix_Scanner/Configuration/file_system_monitoring_cache.html)

HCL's operator reference describes `maxDataAge="0"` as searching the file system directly.
That does not match the behavior observed here; see the divergence table in
[scanner-behavior.md](scanner-behavior.md#where-this-skill-differs-from-hcl-public-documentation).
