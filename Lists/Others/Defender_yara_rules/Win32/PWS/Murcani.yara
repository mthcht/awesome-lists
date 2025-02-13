rule PWS_Win32_Murcani_A_2147667377_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Murcani.A"
        threat_id = "2147667377"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Murcani"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
        $x_1_2 = "CryptUnprotectData" ascii //weight: 1
        $x_1_3 = {66 0f be 91 ?? ?? ?? ?? c1 e2 02 66 89 10 41 40 40 83 f9 25 7c}  //weight: 1, accuracy: Low
        $x_1_4 = "%s\\Winrecv" ascii //weight: 1
        $x_1_5 = "%s\\%c%c%c%c%c%c.TMP" wide //weight: 1
        $x_1_6 = "5e7e8100" wide //weight: 1
        $x_1_7 = {0f 01 4d dc 81 7d de 00 f4 03 80 76 09 81 7d de 00 74 04 80 72 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

