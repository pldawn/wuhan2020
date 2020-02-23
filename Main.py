import re, unicodedata, json


def extract_data(input_path, output_path, filter_fn=lambda x: x):
    cache = ""
    legal = 0
    illegal = 0

    with open(input_path, encoding="utf-8") as fin:
        with open(output_path, 'w', encoding="utf-8") as fout:
            for line in fin:
                line = line.strip("\n")
                line = line.replace("\\n", " ")

                cache += line
                if not cache.endswith('"') or cache.endswith('\t"'):
                    continue
                else:
                    line = cache
                    cache = ""

                line_out = filter_fn(line)

                if line_out:
                    line_out = merge_numerial(line_out)
                    fout.write(line_out + "\n")
                    legal += 1
                else:
                    illegal += 1

    return legal, illegal


def filter_fn_imp(line):
    line = line.split("\t")

    try:
        if len(line[6]) >= 10 and "疫情" in line[5]:
            if "通报" in line[5] or "情况" in line[5]:
                output = line[6].strip()
                output = re.sub(re.escape("\\"), "", output)
                output = output.replace("&nbsp;", "")
                output = output.replace("/n", " ")
                output = output.replace("/", "")
                output = output.replace("(", "（")
                output = output.replace(")", "）")
                output = re.sub("\s+", " ", output)
                output = output[1:-1]
                output.strip()

                return output

            else:
                return ""
        else:
            return ""
    except IndexError as e:
        print(line)
        print(e)
        return ""


def merge_numerial(line):
    output = ""

    for s in line:
        if output == "" or len(output) < 2:
            output += s
            continue

        if unicodedata.category(s) == "Nd" and output[-1] == " " and\
           unicodedata.category(output[-2]) == "Nd":
            output = output[:-1] + s
        else:
            output += s

    return output


def annotate_data(input_path, output_path, annotate_fn=lambda x: x):
    with open(input_path, encoding="utf-8") as fin:
        with open(output_path, 'w', encoding="utf-8") as fout:
            for line in fin:
                try:
                    line = line.strip()
                    output = annotate_fn(line)
                    fout.write(output + "\n")
                except Exception as e:
                    print(e)
                    print(line)
                    raise(e)


def annotate_fn_imp(line):
    # annotate datetime
    ptn_date = "(\d{2,4}年){0,1}\d{1,2}月{0,1}\d{1,2}日"
    line = annotate_pattern(ptn_date, line, "DATE")

    # annotate location
    ptn_location = "(?<=到|去|在)[\u4e00-\u83db\u83dd-\u8d84\u8d86-\u9fa5]+[省市州区县乡镇村道路庄]"
    line = annotate_pattern(ptn_location, line, "LOCATION")

    ptn_location = "(?<=居住|住地|住址|地址|其中|住于|居于|径经)[\u4e00-\u83db\u83dd-\u8d84\u8d86-\u9fa5]+[省市州区县乡镇村道路庄]"
    line = annotate_pattern(ptn_location, line, "LOCATION")

    ptn_location = "(?<=现居)[\u4e00-\u83db\u83dd-\u8d84\u8d86-\u9fa5]+[省市州区县乡镇村道路庄]"
    line = annotate_pattern(ptn_location, line, "LOCATION")

    ptn_location = "(?<=\W)[\u4e00-\u83db\u83dd-\u8d84\u8d86-\u9fa5]+[省市州区县乡镇村道路庄]"
    line = annotate_pattern(ptn_location, line, "LOCATION")

    # annotate person
    ptn_person = "[\u4e00-\u9fa5][某xX] {0,1}[某xX]{0,1}|(新增|确诊|疑似)患者\d*|病例\d+(?=:|：)"
    line = annotate_pattern(ptn_person, line, "PERSON")

    # annotate gender
    ptn_gender = "[男女]性*"
    line = annotate_pattern(ptn_gender, line, "GENDER")

    # annotate age
    ptn_age = "\d{1,3}岁"
    line = annotate_pattern(ptn_age, line, "AGE")

    # annotate case
    ptn_case = "\d+例"
    line = annotate_pattern(ptn_case, line, "CASE")

    # annotate state
    ptn_state = "(新增|现有|累计|已排除|无)*(死亡|出院|在院|疑似|重症|危重症|确诊|轻型|普通型|重型|危重型)"
    line = annotate_pattern(ptn_state, line, "STATE")

    ptn_state = "新增|现有|累计"
    line = annotate_pattern(ptn_state, line, "STATE")

    # annotate O
    output = ""
    line_seg = line.split(" ")

    for seg in line_seg:
        if "/" in seg:
            output += " " + seg
        else:
            for s in seg:
                output += " " + s + "/O"

    output = output.strip()

    return output


def annotate_pattern(pattern, line, flag):
    m = re.finditer(pattern, line)
    indices = []

    for i in m:
        indices.append((i.start(), i.end()))

    for i in range(len(indices), 0, -1):
        i -= 1
        one_indices = indices[i]

        if one_indices[1] - one_indices[0] == 1:
            annotation = line[one_indices[0]] + "/" + flag + "-S"
        elif one_indices[1] - one_indices[0] == 2:
            annotation = line[one_indices[0]] + "/" + flag + "-B " + line[one_indices[1] - 1] + "/" + flag + "-E"
        else:
            annotation = line[one_indices[0]] + "/" + flag + "-B "

            for _ in range(one_indices[0] + 1, one_indices[1] - 1):
                annotation += line[_] + "/" + flag + "-I "

            annotation += line[one_indices[1] - 1] + "/" + flag + "-E"

        line = line[:one_indices[0]] + " " + annotation + " " + line[one_indices[1]:]

    return line


def parse_file(input_path, output_path, parse_fn=lambda x: x):
    failure = 0
    succeed = 0

    with open(input_path, encoding="utf-8") as fin:
        with open(output_path, 'w', encoding="utf-8") as fout:
            for line in fin:
                output = parse_fn(line)

                if output:
                    succeed += 1
                    output_json = json.dumps(output, ensure_ascii=False)
                    fout.write(output_json + "\n")
                else:
                    failure += 1

    print("succeed: %d, failure: %d" % (succeed, failure))


def parse_fn_imp(line):
    offset = -1
    raw_output = []
    output = []
    cache = ""
    cache_flag = ""
    line = line.split(" ")

    # parse raw output from line
    for token in line:
        if token.endswith("-S"):
            offset += 1
            char, flag = token.split("/")
            flag = flag.split("-")[0]
            raw_output.append((char, flag, offset))
            cache = ""
            cache_flag = ""
        elif token.endswith("-B"):
            offset += 1
            char, flag = token.split("/")
            flag = flag.split("-")[0]

            if cache == "":
                cache += char
                cache_flag += flag
            else:
                cache = char
                cache_flag = flag
        elif token.endswith("-I"):
            char, flag = token.split("/")
            flag = flag.split("-")[0]

            if flag == cache_flag:
                cache += char
            else:
                cache = ""
                cache_flag = ""
        elif token.endswith("-E"):
            char, flag = token.split("/")
            flag = flag.split("-")[0]

            if flag == cache_flag:
                cache += char
                raw_output.append((cache, cache_flag, offset))
                cache = ""
                cache_flag = ""
            else:
                cache = ""
                cache_flag = ""
        else:
            # endswith("O") or else
            offset += 1
            cache = ""
            cache_flag = ""

    # merge state
    merge_output = []

    for entity in raw_output:
        if entity[1] == "STATE" and merge_output:
            if merge_output[-1][0] in ("累计", "现有", "新增"):
                merge_output[-1] = (merge_output[-1][0] + entity[0], merge_output[-1][1], merge_output[-1][2])
            else:
                merge_output.append(entity)
        else:
            merge_output.append(entity)

    # parse valid output from raw output
    stack = []

    for ind in range(len(merge_output)):
        entity = merge_output[ind]

        if entity[1] == "PERSON":
            if stack:
                stack = []

        if entity[1] not in stack or entity[1] == "CASE":
            stack.append(entity[1])
        else:
            try:
                # solve "LOCATION STATE CASE LOCATION CASE STATE CASE"'s ambiguity
                if entity[1] == "LOCATION" and stack.index("LOCATION") < stack.index("STATE") \
                        and merge_output[ind + 1][1] == "CASE":
                    if entity[1] not in stack[stack.index("STATE"):] or entity[1] == "CASE":
                        stack.append(entity[1])
                    else:
                        stack = stack[:stack.index("STATE") + stack[stack.index("STATE"):].index(entity[1]) + 1]
                else:
                    stack = stack[:stack.index(entity[1]) + 1]
            except (ValueError, IndexError) as e:
                stack = stack[:stack.index(entity[1]) + 1]

        output.append((entity[0], entity[1], len(stack) - 1))

    return output


def main():
    # input_path_e = r"C:\Users\Mloong\Desktop\several_provinces.csv"
    # output_path_e = r"C:\Users\Mloong\Desktop\clean_data.txt"
    #
    # legal, illegal = extract_data(input_path_e, output_path_e, filter_fn_imp)
    # print(legal, illegal)

    # input_path_a = r"C:\Users\Mloong\Desktop\clean_data.txt"
    # output_path_a = r"C:\Users\Mloong\Desktop\annotate_data.txt"
    #
    # annotate_data(input_path_a, output_path_a, annotate_fn_imp)

    input_path_p = r"C:\Users\Mloong\Desktop\annotate_data.txt"
    output_path_p = r"C:\Users\Mloong\Desktop\parse_result.txt"

    parse_file(input_path_p, output_path_p, parse_fn_imp)


if __name__ == "__main__":
    main()
