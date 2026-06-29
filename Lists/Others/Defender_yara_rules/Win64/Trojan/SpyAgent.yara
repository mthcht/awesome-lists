rule Trojan_Win64_SpyAgent_CX_2147965817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyAgent.CX!MTB"
        threat_id = "2147965817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "captureAndProcessScreenshot" ascii //weight: 5
        $x_5_2 = "beaconLoop" ascii //weight: 5
        $x_5_3 = "detectAVProducts" ascii //weight: 5
        $x_5_4 = "executePE5Exploit" ascii //weight: 5
        $x_5_5 = "TelegramC2Handler" ascii //weight: 5
        $x_5_6 = "handleExfiltrate" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SpyAgent_AMTB_2147972531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyAgent!AMTB"
        threat_id = "2147972531"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Exodus\\exodus.wallet\\unsafe-storage.json" ascii //weight: 1
        $x_1_2 = "\\Downloads\\stealer-go\\builds\\Divinty-Compiler.pdb" ascii //weight: 1
        $x_1_3 = "SELECT guid, value_encrypted FROM local_stored_cvc WHERE value_encrypted IS NOT NULL" ascii //weight: 1
        $x_1_4 = "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

