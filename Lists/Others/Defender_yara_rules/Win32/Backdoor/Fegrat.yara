rule Backdoor_Win32_Fegrat_A_2147770259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fegrat.A!dha"
        threat_id = "2147770259"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fegrat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedFlare/rat/comms.protectedChannel" ascii //weight: 1
        $x_1_2 = "RedFlare/rat/modules/filemgmt.downloadRunner" ascii //weight: 1
        $x_1_3 = "RedFlare/sandals/server.readInRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

