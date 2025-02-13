rule Worm_Win32_Dronzho_A_2147601831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dronzho.A"
        threat_id = "2147601831"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dronzho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "update_myself" ascii //weight: 1
        $x_1_2 = "start_from_here" ascii //weight: 1
        $x_1_3 = "fuck.all.mal.pro" ascii //weight: 1
        $x_1_4 = "SeLoadDriverPrivilege" ascii //weight: 1
        $x_1_5 = "ZwLoadDriver" ascii //weight: 1
        $x_1_6 = "%s\\__power__" ascii //weight: 1
        $x_1_7 = "PersonalBank" ascii //weight: 1
        $x_1_8 = "[AutoRun]" ascii //weight: 1
        $x_1_9 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 22 2e 2e 2e 5c [0-8] 2e 65 78 65 20 6f 5f 64 69 73 6b}  //weight: 1, accuracy: Low
        $x_1_10 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 22 2e 2e 2e 5c [0-8] 2e 65 78 65 20 6f 5f 64 69 73 6b}  //weight: 1, accuracy: Low
        $x_1_11 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 22 2e 2e 2e 5c [0-8] 2e 65 78 65 20 6f 5f 64 69 73 6b}  //weight: 1, accuracy: Low
        $x_1_12 = "System\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_13 = "MAIL From: <%s>" ascii //weight: 1
        $x_1_14 = "%s:\\AutoRun.inf" wide //weight: 1
        $x_1_15 = "%s\\dllcache\\c_20" wide //weight: 1
        $x_1_16 = ".nls" wide //weight: 1
        $x_10_17 = {8d 95 00 fc ff ff 52 68 ?? ?? 42 00 8d 8d 00 f8 ff ff 51 e8 ?? ?? 01 00 83 c4 0c 8d 85 00 fc ff ff 50 68 ?? ?? 42 00 8d 95 00 f4 ff ff 52 e8 ?? ?? 01 00 83 c4 0c 68 80 00 00 00 8d 8d 00 f4 ff ff 51 e8 ?? ?? 02 00 6a 00 8d 85 00 f4 ff ff 50 8d 95 00 f8 ff ff 52 e8 ?? ?? 02 00 8d 8d 00 f4 ff ff 51}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 15 of ($x_1_*))) or
            (all of ($x*))
        )
}

