rule Misleading_Linux_MechBot_DS_301204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/MechBot.DS!MTB"
        threat_id = "301204"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "MechBot"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SPYLIST" ascii //weight: 1
        $x_1_2 = "init: EnergyMech running..." ascii //weight: 1
        $x_1_3 = "No bots in the configfile" ascii //weight: 1
        $x_1_4 = "run ./genuser %s" ascii //weight: 1
        $x_1_5 = "spymsg" ascii //weight: 1
        $x_1_6 = "Deleting bot %s" ascii //weight: 1
        $x_1_7 = "process_incoming_chat" ascii //weight: 1
        $x_1_8 = "check_all_steal" ascii //weight: 1
        $x_1_9 = "send_spy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Linux_MechBot_DT_452517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/MechBot.DT!MTB"
        threat_id = "452517"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "MechBot"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/usr/bin/killall -9 stealth" ascii //weight: 1
        $x_1_2 = "stealth <ip/hostname>" ascii //weight: 1
        $x_1_3 = "CN_BOTDIE" ascii //weight: 1
        $x_1_4 = "(mech_exec) executable has been altered" ascii //weight: 1
        $x_1_5 = "(mech_exec) unable to stat executable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Misleading_Linux_MechBot_DU_462750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/MechBot.DU!MTB"
        threat_id = "462750"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "MechBot"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Acycmech Bot %d Config" ascii //weight: 1
        $x_1_2 = "Acycmech triggerd by admin (hello Zetoo)" ascii //weight: 1
        $x_1_3 = "rm -rf ../mech.set;cp server.txt ../mech.set" ascii //weight: 1
        $x_1_4 = "!telnet@energymech" ascii //weight: 1
        $x_1_5 = "Killing mech: %s" ascii //weight: 1
        $x_1_6 = "Added to mech core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

