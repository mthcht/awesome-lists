rule HackTool_Win32_TwitterBotMaker_A_2147692506_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/TwitterBotMaker.A"
        threat_id = "2147692506"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TwitterBotMaker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Twitter Account Creator Bot" wide //weight: 1
        $x_1_2 = "[AppDataFolder]Kipesoft .INC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_TwitterBotMaker_A_2147692506_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/TwitterBotMaker.A"
        threat_id = "2147692506"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TwitterBotMaker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "client=Kipesoft&random=" wide //weight: 1
        $x_1_2 = "KipeID_Enabled" wide //weight: 1
        $x_1_3 = "http://www.twitter.com/kipesoftinc" wide //weight: 1
        $x_1_4 = "http://www.facebook.com/kipesoftinc" wide //weight: 1
        $x_1_5 = "http://www.kipesoftinc.blogspot.com/" wide //weight: 1
        $x_1_6 = "http://kipesoft-community.boards.net/" wide //weight: 1
        $x_1_7 = "http://kipesoftinc.blogspot.com/p/feedback.html" wide //weight: 1
        $x_1_8 = "http://www.kipe-go-servers.comuf.com/msi_kipeid/login.php" wide //weight: 1
        $x_1_9 = "Twurter V3.22 By Berry Yoo" wide //weight: 1
        $x_1_10 = "Developed by Kipesoft" wide //weight: 1
        $x_1_11 = "lease set a Tweet ID via TuWiter Configuration" wide //weight: 1
        $x_1_12 = "cmd=_s-xclick&hosted_button_id=EXCJUMXG2NDHE" wide //weight: 1
        $x_1_13 = "Twitter Account Creator Bot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

