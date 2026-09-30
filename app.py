import streamlit as st
import requests

st.set_page_config(
    page_title="AI Code Reviewer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Code Reviewer & Security Linter")
st.write(
    "Analyze Python code for security vulnerabilities "
    "and get AI-powered explanations."
)

st.subheader("📁 Upload Python File")

uploaded_file = st.file_uploader(
    "Upload a Python (.py) file",
    type=["py"]
)

uploaded_code = ""

if uploaded_file is not None:
    uploaded_code = uploaded_file.read().decode("utf-8")
    st.success(f"Loaded: {uploaded_file.name}")

st.subheader("📝 Or Paste Python Code")

code = st.text_area(
    "Paste your Python code here:",
    value=uploaded_code,
    height=300,
    placeholder='user_input = input("Enter something:")\nresult = eval(user_input)'
)

if st.button("🔍 Analyze Code", type="primary"):

    if not code.strip():
        st.warning("Please upload a Python file or enter some code first.")

    else:
        with st.spinner("Analyzing code..."):

            try:
                response = requests.post(
                    "http://127.0.0.1:8000/analyze",
                    json={"code": code},
                    timeout=120
                )

                if response.status_code == 200:

                    result = response.json()

                    st.success("Analysis completed!")

                    summary = result.get("summary", {})

                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.metric(
                            "Total Findings",
                            summary.get("total", 0)
                        )

                    with col2:
                        st.metric(
                            "Highest Severity",
                            summary.get("highest_severity", "NONE")
                        )

                    with col3:
                        counts = summary.get("counts", {})
                        st.metric(
                            "High Severity",
                            counts.get("HIGH", 0)
                        )

                    st.divider()

                    findings = result.get("findings", [])

                    if findings:

                        st.subheader("🚨 Security Findings")

                        for finding in findings:

                            severity = finding.get(
                                "severity",
                                "INFO"
                            )

                            st.markdown(
                                f"### {finding.get('rule', 'Unknown')} — "
                                f"{severity}"
                            )

                            st.write(
                                f"**Line:** "
                                f"{finding.get('line', 'N/A')}"
                            )

                            st.write(
                                f"**Issue:** "
                                f"{finding.get('message', '')}"
                            )

                            st.write(
                                f"**Recommendation:** "
                                f"{finding.get('recommendation', '')}"
                            )

                            st.divider()

                    else:
                        st.success(
                            "✅ No security vulnerabilities detected."
                        )

                    explanations = result.get(
                        "ai_explanations",
                        []
                    )

                    if explanations:

                        st.subheader(
                            "🤖 AI Security Explanation"
                        )

                        for explanation in explanations:

                            st.markdown(
                                explanation.get(
                                    "ai_explanation",
                                    "No AI explanation available."
                                )
                            )

                else:

                    st.error(
                        f"API Error: {response.status_code}\n\n"
                        f"{response.text}"
                    )

            except requests.exceptions.ConnectionError:

                st.error(
                    "Could not connect to the FastAPI backend. "
                    "Make sure the API server is running on port 8000."
                )

            except Exception as e:

                st.error(f"Error: {e}")