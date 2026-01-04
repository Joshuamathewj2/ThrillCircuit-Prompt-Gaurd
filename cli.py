import argparse
import sys
import json
from detector import InjectionDetector

def main():
    parser = argparse.ArgumentParser(description="Antigravity Prompt Guard CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'check' command
    check_parser = subparsers.add_parser("check", help="Analyze a prompt for injection risks")
    check_parser.add_argument("prompt", type=str, help="The prompt string to analyze")
    check_parser.add_argument("--config", type=str, default="config.yaml", help="Path to config file")

    # 'server' command
    server_parser = subparsers.add_parser("server", help="Start the API server")
    
    args = parser.parse_args()

    if args.command == "check":
        try:
            detector = InjectionDetector(args.config)
            result = detector.analyze(args.prompt)
            print(json.dumps(result, indent=2))
            
            # Exit with non-zero code if HIGH risk (optional for CI/CD)
            if result['risk_level'] == "HIGH":
                sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

    elif args.command == "server":
        print("Starting API server...")
        # We import here to avoid dependency if just using CLI check (though config imports it anyway)
        from api import app
        app.run(host='0.0.0.0', port=5000)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
