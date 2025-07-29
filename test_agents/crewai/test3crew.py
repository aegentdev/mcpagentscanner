import crewai
from crewai import Agent

print("dads")
Jim = Agent(
    role= "Dad",
    goal="Justa dad",
    backstory="",
    llm="barbeque"
)

