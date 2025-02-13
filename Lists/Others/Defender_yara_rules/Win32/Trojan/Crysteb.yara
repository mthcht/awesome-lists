rule Trojan_Win32_Crysteb_A_2147732030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysteb.A"
        threat_id = "2147732030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysteb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smaters.exe" ascii //weight: 1
        $x_1_2 = "svsmst.exe" ascii //weight: 1
        $x_1_3 = "performer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Crysteb_B_2147732031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysteb.B"
        threat_id = "2147732031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysteb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ext-test-e1718.firebaseapp.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crysteb_C_2147733335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysteb.C"
        threat_id = "2147733335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysteb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pkedcjkdefgpdelpbcmbmeomcjbeemfm" ascii //weight: 1
        $x_1_2 = "ghbmnnjooekpmoecnnnilnnbdlolhkhi" ascii //weight: 1
        $x_1_3 = "iobklfepjocnamgkkbiglidom" ascii //weight: 1
        $x_1_4 = "script-src 'self' https://www.gstatic.com/ https://accounts.google.com https://*.firebaseio.com https://www.googleapis.com; object-src 'self'" ascii //weight: 1
        $x_1_5 = "\\firebase-messaging.js" ascii //weight: 1
        $x_1_6 = "\\firebase-messaging-sw.js" ascii //weight: 1
        $x_1_7 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crysteb_SD_2147733770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysteb.SD!MTB"
        threat_id = "2147733770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysteb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"syncGUID\":\"{13186dc4-4bc2-4c1a-8b4d-ba736d35fdd6}\"" ascii //weight: 1
        $x_1_2 = "{FA1B727D-3970-4561-8AC6-AC8AA7DBA639}" ascii //weight: 1
        $x_1_3 = "\"],\"matches\":[\"http://*/*\", \"https://*/*\"],\"run_at\":\"document_end" ascii //weight: 1
        $x_1_4 = "egefklfmaeogcfhelnamdhgknndnpeim" ascii //weight: 1
        $x_1_5 = "/S /C choice /C Y /N /D Y /T 3 & \"C:\\myapp.exe\" \"C:\\myapp.exe" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Performer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

