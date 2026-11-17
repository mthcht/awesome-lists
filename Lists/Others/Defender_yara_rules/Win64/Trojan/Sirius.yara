rule Trojan_Win64_Sirius_YBB_2147982221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirius.YBB!MTB"
        threat_id = "2147982221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirius"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--window-position=0,0 --no-sandbox --allow-no-sandbox-job --disable-gpu" ascii //weight: 1
        $x_1_2 = "--disable-d3d11 --start-maximized --no-first-run" ascii //weight: 1
        $x_1_3 = "browser-check --disable-sync --disable-background-networking" ascii //weight: 1
        $x_1_4 = ">Welcome to HVNC" ascii //weight: 1
        $x_4_5 = "Global\\RdiShm_%08X" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

