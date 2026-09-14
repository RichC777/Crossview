import { createFileRoute } from "@tanstack/react-router";
import { CodeBlock, Notice, Page, Panel } from "@/components/page";

export const Route = createFileRoute("/package")({
  component: PackagePage,
});

function PackagePage() {
  return (
    <Page
      title="Driver / package"
      lead="Build notes for crossview.sys, cvscan.exe, and the Win32 GUI. There are no prebuilt downloads in this repo."
    >
      <Notice>
        Compile and test-sign on a Windows lab box with Visual Studio 2022 (C++) and a matching WDK.
        This web console never loads the driver.
      </Notice>
      <Panel title="Layout">
        <ul className="space-y-1 font-mono text-xs text-muted">
          <li>windows/shared/CrossViewShared.h — IOCTL protocol</li>
          <li>windows/driver/ — WDM software driver → crossview.sys</li>
          <li>windows/cli/cvscan.c — command-line scanner</li>
          <li>windows/gui/main.c — dark Win32 GUI</li>
          <li>windows/inf/CrossView.inf — optional PnP install</li>
          <li>windows/build.bat / sign.bat</li>
        </ul>
      </Panel>
      <Panel title="Lab load">
        <CodeBlock>{`cd windows
build.bat
bcdedit /set testsigning on
sign.bat path\\to\\testcert.pfx
sc create CrossView type= kernel start= demand binPath= C:\\lab\\crossview.sys
cvscan.exe --fudmodule`}</CodeBlock>
      </Panel>
    </Page>
  );
}
