import re
import ruamel.yaml
file_path = "main.go"
# 라벨명 입력
print("라벨명을 입력해주세요\n")
label = input()
# main.go 파일을 리스트로 읽어옴
with open(file_path) as f:
    lines = f.readlines()
lines = [line.rstrip('\n') for line in lines if 'HandleFunc' in line]
# HandleFunc 메소드를 기준으로 엔드포인트 추출
pattern = r'\.HandleFunc\("([^"]+)",'
endpoints = [re.search(pattern, code).group(1) for code in lines if re.search(pattern, code)]
pattern = r'\{[^/]+\}'
# 중괄호로 감싸진 부분을 *로 대체하여 다시 리스트화
endpoints = [re.sub(pattern, '*', endpoint) for endpoint in endpoints]
# 루트 엔드포인트는 제거 & 중복 제거
endpoints = list(set([e for e in endpoints if e != '/']))

print("엔드포인트의 목록은 다음과 같습니다\n", endpoints)
print("역할명과 접근 가능한 엔드포인트 인덱스를 띄어쓰기로 구분하여 입력해주세요 종료 시 z ex. admin 12345\n")
rb_end = {}
while(True):
    r = input()
    rule = r.split(' ')[0]
    if rule == 'z':
        break
    end = r.split(' ')[1]
    end_list = list(map(int, str(end)))
    rb_end[rule] = end_list

for i in rb_end:
    end_list = [endpoints[i] for i in rb_end[i]]
    name = i+'_ap'
    yaml_data = {
        'apiVersion': 'security.istio.io/v1beta1',
        'kind': 'AuthorizationPolicy',
        'metadata': {
            'name': name,
        },
        'spec': {
            'selector': {
                'matchLabels': {
                    'app': label,
                },
            },
            'action': 'DENY',
            'rules':[
                {
                    'to': [
                        {
                            'operation': {
                                'paths': end_list,
                            },
                        },
                    ],
                    'when': [
                        {
                            'key': 'request.auth.claims[roles]',
                            'notValues': i,
                        },
                    ],
                },
            ]
        },
    }

    yaml = ruamel.yaml.YAML()
    with open('ap_' + i + '.yaml', 'w') as yaml_file:
        yaml.dump(yaml_data, yaml_file)
