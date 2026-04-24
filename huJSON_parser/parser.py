"""
huJSON Parser for Headscale ACL files.
Strips // line comments and /* block comments */  then deserialises into 'HeadscalePolicy' dataclass
Assumption: Parser getting valid huJSON file as input
"""

import json
import re
from typing import Optional
from acl_generator.generator import ACLRule, HeadscalePolicy

class huJSON_Parser:
    def __init__(self, file_path: str):
        self.file_path = file_path
    
    def _strip_comments(self, text:str) -> str:
        result_text = []
        idx = 0
        in_string = False

        while(idx < len(text)):
            ch = text[idx]

            # Parsing within string
            if in_string:
                if ch == '\\':   # escape char: add next char to it also directly (To avoid \" sequences and identify as end of string)
                    result_text.append(ch)
                    idx += 1
                    if idx < len(text):
                        result_text.append(ch)
                        idx += 1
                elif ch == '"':
                    in_string = False       # mark as end of string
                    result_text.append(ch)
                    idx += 1
                else:
                    result_text.append(ch)
                    idx += 1
            else:   # Handling comments
                if ch == '"':
                    in_string = True
                    result_text.append(ch)
                    idx += 1
                elif text[idx:idx+2] == "//":   # line comments: skip to end of the line
                    while(idx < len(text) and text[idx] != '\n'):
                        idx += 1
                elif text[idx:idx+2] == "/*":   # block comments: skip entire block till the string "*/"
                    idx += 2    #skip /*
                    while(idx < len(text) and text[idx:idx+2] != "*/"):
                        idx += 1
                    idx += 2    #skip */
                else:
                    result_text.append(ch)
                    idx += 1

        return ''.join(result_text)
    
    def _remove_trailing_commas(self, text:str) -> str:
        return re.sub(r',\s*([}\]])', r'\1', text)
    
    def _parse_hujson_text(self, text:str) -> str:
        stripped_comments_text = self._strip_comments(text)
        # print(stripped_comments_text)
        # print("---------------------------")
        clean_text = self._remove_trailing_commas(stripped_comments_text)
        return clean_text
    
    def _json_to_HeadScalePolicy(self, json_dict: dict) -> HeadscalePolicy:
        tag_owners = json_dict.get("tagOwners", {})
        auto_approvers = json_dict.get("autoApprovers", {})
        hosts = json_dict.get("hosts")
        acls = []
        for rule_dict in json_dict.get("acls", []):
            acls.append(ACLRule(action=rule_dict.get("action", "accept"), 
                                src=rule_dict.get("src", []), dst=rule_dict.get("dst", []), 
                                proto=rule_dict.get("proto")))
        
        return HeadscalePolicy(tag_owners=tag_owners, acls=acls, auto_approvers=auto_approvers, hosts=hosts)
    
    def parse(self) -> HeadscalePolicy:
        with open(self.file_path, "r") as f:
            file_text = f.read()
        
        cleaned_file_text = self._parse_hujson_text(file_text)
        # print(cleaned_file_text)
        json_dict = json.loads(cleaned_file_text)
        headscalePolicy = self._json_to_HeadScalePolicy(json_dict)
        return headscalePolicy
    
# if __name__ == "__main__":
#     acl_filepath = "sample_acl.txt"
#     parser = huJSON_Parser(acl_filepath)
#     policy = parser.parse()
    # print(policy.to_dict())
    # print(policy.to_hujson())