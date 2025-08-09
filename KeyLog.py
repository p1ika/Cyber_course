from pynput import keyboard
list_of_chars = []
def on_press_key(key):
    global list_of_chars
    if key == keyboard.Key.esc:
        print("Escape pressed. stoping the listener")
        print(list_of_chars)
        print("".join(list_of_chars))
        return False
    else:
        try:
            if key == keyboard.Key.space:
                print("space pressed")
                list_of_chars.append(" ")
            elif key == keyboard.Key.backspace:
                print("delete pressed")
                list_of_chars.pop()
            else:
                char_key = key.char
                print(f"the pressed key is {char_key}")
                list_of_chars.append(char_key)
        except AttributeError:
            print("Special character pressed")
    return True




with keyboard.Listener(on_press=on_press_key) as listener:
    listener.join()

