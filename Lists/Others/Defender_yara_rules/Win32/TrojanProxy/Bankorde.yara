rule TrojanProxy_Win32_Bankorde_A_2147679751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bankorde.A"
        threat_id = "2147679751"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankorde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bitte geben Sie das Passwort ein" ascii //weight: 1
        $x_1_2 = "-r -a -s -h %Windir%\\systEm32\\drivErs\\Etc\\hosts" ascii //weight: 1
        $x_1_3 = {5c 45 74 63 5c 68 6f 73 74 73 0d 0a 45 63 68 6f 20}  //weight: 1, accuracy: High
        $x_1_4 = "BaNKIng.nonghyup.com>>c:/" ascii //weight: 1
        $x_1_5 = "BaNKIng.SHINHAN.com>>c:/" ascii //weight: 1
        $x_1_6 = "myBaNK.IBK.co.kr>>c:/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

