rule Backdoor_IRC_Zapchast_AZ_2147597378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:IRC/Zapchast.AZ"
        threat_id = "2147597378"
        type = "Backdoor"
        platform = "IRC: mIRC/pIRC scripts"
        family = "Zapchast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\RECYCLER\\S-1-5-21-606747145-1085031214-725345543-500\\sup.exe" ascii //weight: 10
        $x_10_2 = "a_friend.exe" ascii //weight: 10
        $x_10_3 = "mirc.ini" ascii //weight: 10
        $x_10_4 = "users.ini" ascii //weight: 10
        $x_1_5 = "popups.txt" ascii //weight: 1
        $x_1_6 = "Necazul.users.undernet.org1" ascii //weight: 1
        $x_1_7 = "servers.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

