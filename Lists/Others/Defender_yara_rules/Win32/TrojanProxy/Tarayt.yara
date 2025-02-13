rule TrojanProxy_Win32_Tarayt_A_2147717970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tarayt.A"
        threat_id = "2147717970"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarayt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User-Agent: ace4956e-736e-11e6-9584-d7165ca591df" ascii //weight: 1
        $x_1_2 = "GET /pixelid2/s2s.php?" ascii //weight: 1
        $x_1_3 = "adv=NetworkManager&shortname=NetworkManager&key=" ascii //weight: 1
        $x_1_4 = "M3RedSeSKv75YQ5FN3374TWtq9Rurekz&time=%u" ascii //weight: 1
        $x_1_5 = {61 56 6f 00 6d 74 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 54 59 4e 4b 41 4a 50 33 30 5a 39 41 51 00}  //weight: 1, accuracy: High
        $x_1_7 = {79 65 55 21 48 6c 71 4d 50 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

