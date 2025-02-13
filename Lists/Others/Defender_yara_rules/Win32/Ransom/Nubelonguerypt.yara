rule Ransom_Win32_Nubelonguerypt_A_2147722904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nubelonguerypt.A"
        threat_id = "2147722904"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nubelonguerypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\yl.ini" ascii //weight: 1
        $x_1_2 = {2e 79 6c 00 2a 2e 2a}  //weight: 1, accuracy: High
        $x_1_3 = {69 63 6f 2e 69 63 6f [0-4] 31 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_4 = "*.e|*.doc|*.jpg|*.png|*.txt|*.pdf|*.wps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

