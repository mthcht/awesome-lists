rule Backdoor_Win32_SpyAgent_A_2147611338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SpyAgent.A"
        threat_id = "2147611338"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\wpcap.dll" ascii //weight: 1
        $x_1_2 = "mail.stealth-email.com:26" ascii //weight: 1
        $x_1_3 = "%s\\csrss.exe" ascii //weight: 1
        $x_1_4 = "Computer IP Address: %s" ascii //weight: 1
        $x_1_5 = "Content-Type: text/plain; charset=us-ascii" ascii //weight: 1
        $x_1_6 = "SPYAGENT4HASHCIPHER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

