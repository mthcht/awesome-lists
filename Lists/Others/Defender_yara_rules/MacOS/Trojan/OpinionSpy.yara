rule Trojan_MacOS_OpinionSpy_2147735636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy"
        threat_id = "2147735636"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "securestudies.com" ascii //weight: 2
        $x_1_2 = "SurveyQuestionViewController" ascii //weight: 1
        $x_3_3 = "PremierOpinion" ascii //weight: 3
        $x_1_4 = "poDemo.txt" ascii //weight: 1
        $x_1_5 = "/private/tmp/" ascii //weight: 1
        $x_1_6 = "Please complete this short survey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_A_2147745382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.A!MTB"
        threat_id = "2147745382"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ossbrandroot%" ascii //weight: 1
        $x_1_2 = "post.securestudies.com:443/precampaigncheck.aspx" ascii //weight: 1
        $x_1_3 = "Campaign_Check_Url" ascii //weight: 1
        $x_1_4 = "/private/tmp/installtmp/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_B_2147745472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.B!MTB"
        threat_id = "2147745472"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OSMIMPQ.socket" ascii //weight: 1
        $x_1_2 = "ruleSecrectKey" ascii //weight: 1
        $x_1_3 = "MacMeterAgent" ascii //weight: 1
        $x_1_4 = "/var/run/.osm_pqm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_C_2147746265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.C!MTB"
        threat_id = "2147746265"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "securestudies.com" ascii //weight: 1
        $x_1_2 = "ruleSecrectKey" ascii //weight: 1
        $x_1_3 = "%ossbrandroot%" ascii //weight: 1
        $x_1_4 = "Macmeter load cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_D_2147747835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.D!MTB"
        threat_id = "2147747835"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "comscore/workingcopy/MacSniffer" ascii //weight: 1
        $x_1_2 = "InjectCode.app/Contents/Resources/macmeterhk.bundle" ascii //weight: 1
        $x_1_3 = "app/Contents/Resources/macmeterPdf" ascii //weight: 1
        $x_1_4 = "ossproxy.exe" ascii //weight: 1
        $x_1_5 = "rules.securestudies.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_OpinionSpy_E_2147747852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.E!MTB"
        threat_id = "2147747852"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "comscore/workingcopy/MacSniffer/" ascii //weight: 1
        $x_1_2 = "var/tmp/OSMIMPQ.socket" ascii //weight: 1
        $x_1_3 = "swizzlesafari" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_F_2147748623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.F!MTB"
        threat_id = "2147748623"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "campaignid.txt" ascii //weight: 1
        $x_1_2 = "tmp/poDemo.txt" ascii //weight: 1
        $x_1_3 = "MacMeter2/trunk/MacAnalyser/algorithm/" ascii //weight: 1
        $x_1_4 = "dpd.securestudies.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_G_2147748723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.G!MTB"
        threat_id = "2147748723"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "post.securestudies.com/packages/" ascii //weight: 2
        $x_1_2 = "/MContentI3.gz" ascii //weight: 1
        $x_1_3 = "ZXT_MAC/Bundles/Download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_H_2147753223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.H!MTB"
        threat_id = "2147753223"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uninstall macmeter" ascii //weight: 1
        $x_3_2 = "/comscore/workingcopy/MacSniffer/UnInstallTool" ascii //weight: 3
        $x_1_3 = "UninstallMainController setBrand:" ascii //weight: 1
        $x_1_4 = "uninstallhelpertool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_I_2147753469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.I!MTB"
        threat_id = "2147753469"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "securestudies.com" ascii //weight: 2
        $x_2_2 = "macmeter2/master/MacAnalyser/macanalyser" ascii //weight: 2
        $x_1_3 = ".app/Contents/Resources/mmij.app/Contents/MacOS/mmij" ascii //weight: 1
        $x_1_4 = "/tmp/tmpFile.XXXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_OpinionSpy_J_2147759287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.J!MTB"
        threat_id = "2147759287"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "securestudies.com" ascii //weight: 1
        $x_1_2 = "PremierOpinion is a Comscore brand, provided by VoiceFive Inc., a Comscore company." ascii //weight: 1
        $x_1_3 = "poDemo.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_OpinionSpy_A_2147814035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OpinionSpy.A!xp"
        threat_id = "2147814035"
        type = "Trojan"
        platform = "MacOS: "
        family = "OpinionSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "securestudies.com" ascii //weight: 2
        $x_2_2 = {6d 61 63 6d 65 74 65 72 32 2f [0-8] 2f 4d 61 63 41 6e 61 6c 79 73 65 72 2f}  //weight: 2, accuracy: Low
        $x_2_3 = "www.premieropinion.com" ascii //weight: 2
        $x_2_4 = "/private/tmp/PoPathxD/poinstaller" ascii //weight: 2
        $x_2_5 = "com.VoiceFive.PremierOpinion" ascii //weight: 2
        $x_2_6 = "QTC8AXGL44" ascii //weight: 2
        $x_1_7 = "campaign_id=" ascii //weight: 1
        $x_1_8 = "usr/sbin/lsof -a -p %d +D %s" ascii //weight: 1
        $x_1_9 = "/tmp/tmpFile.XXXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

