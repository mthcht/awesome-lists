rule Ransom_Win32_Lebanacrypt_A_2147726082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lebanacrypt.A"
        threat_id = "2147726082"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lebanacrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SHADOW_COPY_DIRS" ascii //weight: 1
        $x_1_2 = "DISALLOW_APP_REDIRECTS" ascii //weight: 1
        $x_1_3 = "CODE_DOWNLOAD_DISABLED" ascii //weight: 1
        $x_1_4 = "DISALLOW_APP_BASE_PROBING" ascii //weight: 1
        $x_1_5 = "BINPATH_PROBE_ONLY" ascii //weight: 1
        $x_2_6 = "iCoreX#1337" ascii //weight: 2
        $x_3_7 = "annabelle85x9tbxiyki.onion" ascii //weight: 3
        $x_3_8 = "annabelle59j3mbtyyki.onion" ascii //weight: 3
        $x_5_9 = {bb e0 07 8e c3 8e db b8 16 02 b9 02 00 b6 00 bb 00 00 cd 13 31 c0 89 c3 89 c1 89 c2 be 00 00 bf ?? ?? ac 81 fe ?? ?? 73 31 3c 80 73 02 eb 0f}  //weight: 5, accuracy: Low
        $x_5_10 = {b9 00 20 00 00 f3 a5 5f 5e 6a 00 8d 45 ?? 50 68 00 80 00 00 8d 85 ?? ?? ff ff 50 53 e8}  //weight: 5, accuracy: Low
        $x_2_11 = "shutdown.exe -r -f -t 0" ascii //weight: 2
        $x_2_12 = "taskkill.exe /F /IM wininit.exe" ascii //weight: 2
        $x_1_13 = "PhysicalDrive4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

