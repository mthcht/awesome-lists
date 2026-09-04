rule Ransom_Win32_Darkfall_LR_2147977531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Darkfall.LR!MTB"
        threat_id = "2147977531"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkfall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "78"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES HAVE BEEN ENCRYPTED BY DARKFALL" ascii //weight: 1
        $x_2_2 = "All your important documents, photos, and data have been encrypted." ascii //weight: 2
        $x_3_3 = "To recover your files, you must pay a ransom in any cryptocurrency." ascii //weight: 3
        $x_4_4 = "After contacting us through the chat interface, we are able to decrypt your files." ascii //weight: 4
        $x_5_5 = "You have 72 hours before the decryption key is permanently deleted." ascii //weight: 5
        $x_6_6 = "Any attempt to decrypt the files yourself or use third-party tools will result in permanent data loss." ascii //weight: 6
        $x_7_7 = "\\n\\n**DECRYPTION KEY:**" ascii //weight: 7
        $x_8_8 = "ransom_note.txt" ascii //weight: 8
        $x_9_9 = "FILES ENCRYPTED" ascii //weight: 9
        $x_10_10 = "Type your message and press Enter to chat with us" ascii //weight: 10
        $x_11_11 = "DARKFALL_RANSOMWARE_2024" ascii //weight: 11
        $x_12_12 = "C:\\*.darkfall" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

