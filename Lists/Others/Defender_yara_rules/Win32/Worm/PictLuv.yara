rule Worm_Win32_PictLuv_AYA_2147930966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/PictLuv.AYA!MTB"
        threat_id = "2147930966"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "PictLuv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aaa_TouchMeNot_.txt" wide //weight: 2
        $x_2_2 = "WINDOWS\\SYSTEM32\\hit.exe" wide //weight: 2
        $x_1_3 = "www.love.greetings.com" ascii //weight: 1
        $x_1_4 = "www.net_speed.txt.com" ascii //weight: 1
        $x_1_5 = "www.lovecalc.txt.com" ascii //weight: 1
        $x_1_6 = "www.picture.advani.tehelka.com" ascii //weight: 1
        $x_1_7 = "File currepted" ascii //weight: 1
        $x_1_8 = "This text file contains some calculations related to speed of net connections, verify it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

