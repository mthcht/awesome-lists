rule Backdoor_Win32_Zopharp_A_2147633893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zopharp.A"
        threat_id = "2147633893"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zopharp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "require_once('Functions/Zombies.php');" ascii //weight: 1
        $x_1_2 = "require_once('Functions/Pharming.php');" ascii //weight: 1
        $x_1_3 = "file(UrlServer . \"/Admin/FunctionsClient/Select.php?action1=\".$A.\"&action2=\".$B.\"&action3=\".$C);" ascii //weight: 1
        $x_1_4 = "$Zombies = createArray('zombis' , NameMaquina , 'name');" ascii //weight: 1
        $x_1_5 = "ChatWnd.SendMessage(Mensajes[Random]);" ascii //weight: 1
        $x_1_6 = "fopen ( \"c:/windows/system32/drivers/etc/hosts\", \"a+\" );" ascii //weight: 1
        $x_1_7 = "fopen($H . \"Scripts/Facebook/Facebook.txt\" , \"a+\");" ascii //weight: 1
        $x_1_8 = "fopen(UrlServer . \"/Admin/FunctionsClient/Update.php?\" . $Url  , 'r');" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

