#!/bin/bash

# apply existing migrations
python3 manage.py migrate

# Migrations ship with the source code. Generating them at runtime
# (as earlier versions did) produced unreviewed, install-specific
# migrations that conflict with upstream ones on update.
python3 manage.py makemigrations --check --dry-run > /dev/null 2>&1 || \
  echo "WARNING: models and migrations are out of sync. Run 'make migrations' in a dev checkout and commit the result."


python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

# Firefox is installed in the image (see Dockerfile).

# Third-party Python tools get their own virtualenv so their pinned
# dependencies can't break reNgine's (or each other's).
# usage: tool_venv <tool_dir> [pip args...]
tool_venv() {
  local dir=$1; shift
  if [ ! -x "$dir/.venv/bin/python" ]; then
    python3 -m venv "$dir/.venv"
  fi
  "$dir/.venv/bin/python" -m pip install -q --upgrade pip
  "$dir/.venv/bin/python" -m pip install -q "$@" || echo "WARNING: dependency install failed for $dir"
}

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]
then
  echo "Making Wordlist directory"
  mkdir /usr/src/wordlist
fi

if [ ! -f "/usr/src/wordlist/" ]
then
  echo "Downloading Default Directory Bruteforce Wordlist"
  wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt
fi

# check if default wordlist for amass exists
if [ ! -f /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt ];
then
  echo "Downloading Deepmagic top 50000 Wordlist"
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt
fi

# clone Sublist3r
if [ ! -d "/usr/src/github/Sublist3r" ]
then
  echo "Cloning Sublist3r"
  git clone https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r
fi
tool_venv /usr/src/github/Sublist3r -r /usr/src/github/Sublist3r/requirements.txt

# clone OneForAll
if [ ! -d "/usr/src/github/OneForAll" ]
then
  echo "Cloning OneForAll"
  git clone https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll
fi
tool_venv /usr/src/github/OneForAll -r /usr/src/github/OneForAll/requirements.txt

# clone eyewitness
if [ ! -d "/usr/src/github/EyeWitness" ]
then
  echo "Cloning EyeWitness"
  git clone https://github.com/FortyNorthSecurity/EyeWitness /usr/src/github/EyeWitness
  # pip install -r /usr/src/github/Eyewitness/requirements.txt
fi

# clone theHarvester (pinned: newer releases require Python >= 3.14)
THEHARVESTER_VERSION=4.11.1
if [ -d "/usr/src/github/theHarvester" ] && [ ! -f "/usr/src/github/theHarvester/pyproject.toml" -o "$(git -C /usr/src/github/theHarvester describe --tags 2>/dev/null)" != "$THEHARVESTER_VERSION" ]
then
  echo "Replacing outdated theHarvester checkout (keeping api-keys.yaml)"
  [ -f /usr/src/github/theHarvester/api-keys.yaml ] && cp /usr/src/github/theHarvester/api-keys.yaml /tmp/theHarvester-api-keys.yaml
  rm -rf /usr/src/github/theHarvester
fi
if [ ! -d "/usr/src/github/theHarvester" ]
then
  echo "Cloning theHarvester $THEHARVESTER_VERSION"
  git clone --depth 1 --branch $THEHARVESTER_VERSION https://github.com/laramies/theHarvester /usr/src/github/theHarvester
fi
[ -f /tmp/theHarvester-api-keys.yaml ] && mv /tmp/theHarvester-api-keys.yaml /usr/src/github/theHarvester/api-keys.yaml
tool_venv /usr/src/github/theHarvester /usr/src/github/theHarvester
# reNgine edits api-keys.yaml / proxies.yaml in the checkout root;
# theHarvester 4.x reads them from ~/.theHarvester
for f in api-keys.yaml proxies.yaml; do
  [ -f "/usr/src/github/theHarvester/$f" ] || cp "/usr/src/github/theHarvester/theHarvester/data/$f" "/usr/src/github/theHarvester/$f"
done
ln -sfn /usr/src/github/theHarvester ~/.theHarvester

# clone vulscan
if [ ! -d "/usr/src/github/scipag_vulscan" ]
then
  echo "Cloning Nmap Vulscan script"
  git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan
  echo "Symlinking to nmap script dir"
  ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan
  echo "Usage in reNgine, set vulscan/vulscan.nse in nmap_script scanEngine port_scan config parameter"
fi

# install h8mail in its own venv, exposed on PATH
mkdir -p /opt/h8mail
tool_venv /opt/h8mail h8mail
ln -sf /opt/h8mail/.venv/bin/h8mail /usr/local/bin/h8mail

# install gf patterns
if [ ! -d "/root/Gf-Patterns" ];
then
  echo "Installing GF Patterns"
  mkdir -p ~/.gf
  git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf-src && cp /tmp/gf-src/examples/*.json ~/.gf && rm -rf /tmp/gf-src
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
  mv ~/Gf-Patterns/*.json ~/.gf
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]
then
  mkdir /usr/src/scan_results
fi

# test tools, required for configuration
naabu && subfinder && amass
nuclei

if [ ! -d "/root/nuclei-templates/geeknik_nuclei_templates" ];
then
  echo "Installing Geeknik Nuclei templates"
  git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates
else
  echo "Removing old Geeknik Nuclei templates and updating new one"
  rm -rf ~/nuclei-templates/geeknik_nuclei_templates
  git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates
fi

if [ ! -f ~/nuclei-templates/ssrf_nagli.yaml ];
then
  echo "Downloading ssrf_nagli for Nuclei"
  wget https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O ~/nuclei-templates/ssrf_nagli.yaml
fi

if [ ! -d "/usr/src/github/CMSeeK" ]
then
  echo "Cloning CMSeeK"
  git clone https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK
fi
tool_venv /usr/src/github/CMSeeK -r /usr/src/github/CMSeeK/requirements.txt

# clone ctfr
if [ ! -d "/usr/src/github/ctfr" ]
then
  echo "Cloning CTFR"
  git clone https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr
fi
tool_venv /usr/src/github/ctfr -r /usr/src/github/ctfr/requirements.txt

# clone gooFuzz
if [ ! -d "/usr/src/github/goofuzz" ]
then
  echo "Cloning GooFuzz"
  git clone https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz
  chmod +x /usr/src/github/goofuzz/GooFuzz
fi

# httpx seems to have issue, use alias instead!!!
echo 'alias httpx="/go/bin/httpx"' >> ~/.bashrc

loglevel='info'
if [ "$DEBUG" == "1" ]; then
    loglevel='debug'
fi

generate_worker_command() {
    local queue=$1
    local concurrency=$2
    local worker_name=$3
    local app=${4:-"reNgine.tasks"}
    local directory=${5:-"/usr/src/app/reNgine/"}

    local base_command="celery -A $app worker --pool=gevent --optimization=fair --autoscale=$concurrency,1 --loglevel=$loglevel -Q $queue -n $worker_name"

    if [ "$DEBUG" == "1" ]; then
        echo "watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"$directory\" -- $base_command &"
    else
        echo "$base_command &"
    fi
}

echo "Starting Celery Workers..."

commands=""

# Main scan worker
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/reNgine/\" -- celery -A reNgine.tasks worker --loglevel=$loglevel --optimization=fair --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &"$'\n'
else
    commands+="celery -A reNgine.tasks worker --loglevel=$loglevel --optimization=fair --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &"$'\n'
fi

# API shared task worker
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/api/\" -- celery -A api.shared_api_tasks worker --pool=gevent --optimization=fair --concurrency=30 --loglevel=$loglevel -Q api_queue -n api_worker &"$'\n'
else
    commands+="celery -A api.shared_api_tasks worker --pool=gevent --concurrency=30 --optimization=fair --loglevel=$loglevel -Q api_queue -n api_worker &"$'\n'
fi

# worker format: "queue_name:concurrency:worker_name"
workers=(
    "initiate_scan_queue:30:initiate_scan_worker"
    "subscan_queue:30:subscan_worker"
    "report_queue:20:report_worker"
    "send_notif_queue:10:send_notif_worker"
    "send_task_notif_queue:10:send_task_notif_worker"
    "send_file_to_discord_queue:5:send_file_to_discord_worker"
    "send_hackerone_report_queue:5:send_hackerone_report_worker"
    "parse_nmap_results_queue:10:parse_nmap_results_worker"
    "geo_localize_queue:20:geo_localize_worker"
    "query_whois_queue:10:query_whois_worker"
    "remove_duplicate_endpoints_queue:30:remove_duplicate_endpoints_worker"
    "run_command_queue:50:run_command_worker"
    "query_reverse_whois_queue:10:query_reverse_whois_worker"
    "query_ip_history_queue:10:query_ip_history_worker"
    "llm_queue:30:llm_worker"
    "dorking_queue:10:dorking_worker"
    "osint_discovery_queue:10:osint_discovery_worker"
    "h8mail_queue:10:h8mail_worker"
    "theHarvester_queue:10:theHarvester_worker"
    "send_scan_notif_queue:10:send_scan_notif_worker"
)

for worker in "${workers[@]}"; do
    IFS=':' read -r queue concurrency worker_name <<< "$worker"
    commands+="$(generate_worker_command "$queue" "$concurrency" "$worker_name")"$'\n'
done
commands="${commands%&}"

eval "$commands"

wait