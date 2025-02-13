rule TrojanDownloader_Win32_SysUpdate_A_2147730964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SysUpdate.A"
        threat_id = "2147730964"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SysUpdate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "host.UI.RawUI.BufferSize" wide //weight: 1
        $x_1_2 = "new-object System.Management.Automation.Host.Size(1024,50);\" \"%s\" 2> \"%s\"" wide //weight: 1
        $x_1_3 = "Release\\stubs\\x86\\Updater.pdb" ascii //weight: 1
        $x_1_4 = "Windows Driver System Updat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

