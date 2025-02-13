rule Trojan_Win32_Covically_A_2147764132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Covically.A!dha"
        threat_id = "2147764132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Covically"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 43 6f 76 69 63 5c 4d 6f 64 75 6c 65 73 5c [0-16] 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_1_2 = "config.dat" ascii //weight: 1
        $x_1_3 = ";$t = '';for($i=0;$i -lt $a.Length;$i+=3){$t += [char](([int]($a[$i..($i+2)] -join ''))-3)};iex($t);" ascii //weight: 1
        $x_1_4 = "$a=get-content" ascii //weight: 1
        $x_1_5 = ",DllRegisterServer" ascii //weight: 1
        $x_1_6 = "function bdec($in){$out" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

