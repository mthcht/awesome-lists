rule Trojan_Win32_AnchorLoader_A_2147766847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AnchorLoader.A!ibt"
        threat_id = "2147766847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AnchorLoader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 61 33 c0 89 45 f6 66 89 ?? ?? 58 6a 6e 66 89 ?? ?? 58 6a 63 66 89 ?? ?? 58 6a 68 66 89 ?? ?? 58 6a 6f 66 89 ?? ?? 58 6a 72 66 89 ?? ?? 58 66 89 ?? ?? 33 c0 66 89 ?? ?? 8d 45 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "Anchor_x86.exe" ascii //weight: 1
        $x_1_3 = "Release\\Anchor_x86.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AnchorLoader_A_2147766847_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AnchorLoader.A!ibt"
        threat_id = "2147766847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AnchorLoader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WinHTTP loader/1.0" ascii //weight: 10
        $x_10_2 = "/1001/" ascii //weight: 10
        $x_10_3 = "cmd.exe /C timeout 5 && sc.exe stop %S" ascii //weight: 10
        $x_10_4 = "/C timeout 30 && sc.exe delete %S   /C timeout 40" ascii //weight: 10
        $x_10_5 = "anchorDNS_x64" ascii //weight: 10
        $x_10_6 = "anchorInstaller_x86" ascii //weight: 10
        $x_10_7 = "Anchor_x64" ascii //weight: 10
        $x_10_8 = "anchorDiag" ascii //weight: 10
        $x_1_9 = "Control_RunDLL" ascii //weight: 1
        $x_1_10 = "Task autoupdate" ascii //weight: 1
        $x_1_11 = "runcommand(%s), pid 0" ascii //weight: 1
        $x_1_12 = "[LOG_EMERG]" ascii //weight: 1
        $x_1_13 = "[LOG_ALERT]" ascii //weight: 1
        $x_1_14 = "hIcmpFile error:" ascii //weight: 1
        $x_1_15 = "created process \"%s\", pid %i" ascii //weight: 1
        $x_1_16 = "wtfismyip.com" ascii //weight: 1
        $x_1_17 = "icanhazip.com" ascii //weight: 1
        $x_5_18 = "hanc" ascii //weight: 5
        $x_5_19 = "TriggerDaily" ascii //weight: 5
        $x_5_20 = "TriggerLogon" ascii //weight: 5
        $x_5_21 = "/plain/clientip" ascii //weight: 5
        $x_5_22 = "get command: incode %s" ascii //weight: 5
        $x_5_23 = "where guid? who will do it?" ascii //weight: 5
        $x_5_24 = "SvchostPushServiceGlobals" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_1_*))) or
            ((6 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

