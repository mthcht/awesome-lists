rule Ransom_Win32_WallStreet_AN_2147982242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WallStreet.AN!MTB"
        threat_id = "2147982242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WallStreet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "No SeDebugPrivilege (not admin?) - skipping TrustedInstaller" ascii //weight: 1
        $x_1_2 = "Service already marked for deletion" ascii //weight: 1
        $x_1_3 = "Browse list returned %lu hosts" ascii //weight: 1
        $x_1_4 = "Started (DEBUG)" ascii //weight: 1
        $x_1_5 = "[DBG] enc=%lu skip=%lu(E:%lu L:%lu X:%lu) post=%lu active=%lu" ascii //weight: 1
        $x_2_6 = "\\System32\\vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
        $x_1_7 = "Scanning subnet of" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

