import subprocess
import os

out_dir = r"C:\Users\atpad\AgentBlackBox\assets\video"
os.makedirs(out_dir, exist_ok=True)

poster1 = r"C:\Users\atpad\AgentBlackBox\assets\posters\poster1_flight_recorder.png"
poster2 = r"C:\Users\atpad\AgentBlackBox\assets\posters\poster2_pr_review_engine.png"
poster3 = r"C:\Users\atpad\AgentBlackBox\assets\posters\poster3_universal_hooks.png"
audio = r"C:\Users\atpad\AgentBlackBox\agentblackbox_voiceover.mp3"
output_video = os.path.join(out_dir, "agentblackbox_product_overview.mp4")

# We create 3 segments of 32s each with subtle fade in/out
# Segment 1: 0 - 32s
seg1 = os.path.join(out_dir, "seg1.mp4")
seg2 = os.path.join(out_dir, "seg2.mp4")
seg3 = os.path.join(out_dir, "seg3.mp4")
concat_txt = os.path.join(out_dir, "concat.txt")

print("Rendering Segment 1...")
subprocess.run([
    "ffmpeg", "-y", "-loop", "1", "-i", poster1, "-c:v", "libx264", "-t", "32",
    "-pix_fmt", "yuv420p", "-vf", "fade=t=in:st=0:d=1,fade=t=out:st=31:d=1",
    "-r", "30", seg1
], check=True)

print("Rendering Segment 2...")
subprocess.run([
    "ffmpeg", "-y", "-loop", "1", "-i", poster2, "-c:v", "libx264", "-t", "32",
    "-pix_fmt", "yuv420p", "-vf", "fade=t=in:st=0:d=1,fade=t=out:st=31:d=1",
    "-r", "30", seg2
], check=True)

print("Rendering Segment 3...")
subprocess.run([
    "ffmpeg", "-y", "-loop", "1", "-i", poster3, "-c:v", "libx264", "-t", "32",
    "-pix_fmt", "yuv420p", "-vf", "fade=t=in:st=0:d=1,fade=t=out:st=31:d=1",
    "-r", "30", seg3
], check=True)

# Write concat list
with open(concat_txt, "w") as f:
    f.write(f"file '{seg1.replace('\\', '/')}'\n")
    f.write(f"file '{seg2.replace('\\', '/')}'\n")
    f.write(f"file '{seg3.replace('\\', '/')}'\n")

print("Concatenating and mixing audio overview...")
subprocess.run([
    "ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", concat_txt,
    "-i", audio, "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
    "-shortest", output_video
], check=True)

# Clean intermediate segments
for s in [seg1, seg2, seg3, concat_txt]:
    if os.path.exists(s):
        os.remove(s)

print(f"🎉 Product Overview Video ready at: {output_video}")
